# -*- coding: utf-8 -*-
# Copyright 2021 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Task for analysing static creds."""

import json
import logging
import os

from turbinia import TurbiniaException

from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.lib.utils import extract_artifacts
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask

YARA_FILE = os.path.dirname(__file__) + "/yara/static_creds.yara"
log = logging.getLogger('turbinia')


class StaticCredsTaskException(TurbiniaException):
  """Class for exceptions in this task."""


class StaticCredsTask(TurbiniaTask):
  """Task to look for any static creds."""

  REQUIRED_STATES = [
      state.ATTACHED, state.CONTAINER_MOUNTED, state.DECOMPRESSED
  ]

  def run(self, evidence, result):
    """Run the Static Creds worker.

    Args:
      evidence (Evidence object):  The evidence to process
      result (TurbiniaTaskResult): The object to place task results into.
    Returns:
      TurbiniaTaskResult object.
    """
    # Where to store the output files.
    output_file_path = os.path.join(self.output_dir, 'static_creds.txt')
    plaso_file_path = os.path.join(self.tmp_dir, 'out.plaso')
    jsonl_file_path = os.path.join(self.tmp_dir, 'out.jsonl')

    # What type of evidence we should output.
    findings = {}
    output_evidence = ReportText(source_path=output_file_path)

    try:
      # First step - using log2timeline, run the yara rules against the evidence.
      log.info("Running yara via log2timeline.....")
      self._run_log2timeline(evidence.local_path, plaso_file_path, result)

      # Second step - using psort, output the findings to something we can work with (easier than sqlite)
      log.info("Log2timeline complete. psort'ing.....")
      self._run_psort(plaso_file_path, jsonl_file_path, result)
    except StaticCredsTaskException as e:
      log.error("Failure in StaticCredsTask: {0:s}".format(str(e)))
      result.close(self, success=False, status=str(e))
      return result

    # Load up & filter the results
    with open(jsonl_file_path, 'r') as json_file:
      for line in json_file:
        parsed = json.loads(line)
        if 'yara_match' in parsed and parsed['yara_match'] != "":
          for rule in parsed['yara_match'].split(','):
            if rule not in findings:
              findings[rule] = []
            if parsed['filename'] not in findings[rule]:
              findings[rule].append(parsed['filename'])

    if len(findings):
      report = self._generate_report(findings)
      output_evidence.text_data = report
      result.report_priority = Priority.HIGH
      result.report_data = report

      # Write the report to the output file.
      with open(output_file_path, 'wb') as fh:
        fh.write(output_evidence.text_data.encode('utf-8'))

      result.add_evidence(output_evidence, evidence.config)
      result.close(self, success=True, status='Possible static creds found')
    else:
      result.report_priority = Priority.LOW
      result.close(self, success=True, status='No static creds found')

    return result

  def _run_log2timeline(self, src_path, output_path, result):
    """Runs log2timeline using the yara rules for static creds.

    Args:
      src_path (str): The evidence path to use.
      output_path (str): The destination plaso output file.
      result (TurbiniaTaskResult): The Tasks result object.

    Raises:
      StaticCredsTaskException: If the psort fails.
    """
    cmd = [
        'log2timeline.py', '--yara_rules', YARA_FILE, '--parsers', 'filestat',
        '--unattended', '--partitions', 'all', '--volumes', 'all',
        '--storage_file', output_path, '--hashers', 'none', '--status_view',
        'none', src_path
    ]
    log.info("Executing: {0:s}".format(" ".join(cmd)))
    ret, _ = self.execute(cmd, result, close=False)

    if ret:
      raise StaticCredsTaskException("log2timeline failure.")

  def _run_psort(self, src_plaso, output_path, result):
    """Runs log2timeline using the yara rules for static creds.

    Args:
      src_plaso (str): The input plaso file.
      output_path (str): The destination jsonl output file.
      result (TurbiniaTaskResult): The Tasks result object.

    Raises:
      StaticCredsTaskException: If the psort fails.
    """
    cmd = [
        'psort.py', '--status_view', 'none', '-o', 'json_line', '-w',
        output_path, src_plaso
    ]
    log.info("Executing: {0:s}".format(" ".join(cmd)))
    ret, _ = self.execute(cmd, result, close=False)

    if ret:
      raise StaticCredsTaskException("psort failure.")

  def _generate_report(self, findings):
    """Generate the report text based on the task findings.
    
    Args:
      findings (dict(str, list[str])) The generated findings of yara rule names
        mapped to files.
    Returns:
      (str) The report data.
        """
    report = []

    for rule in findings:
      report.append(
          "Match(es) for rule {0:s} found in the following files:".format(rule))
      for file in findings[rule]:
        report.append(fmt.bullet(file))

    return "\n".join(report)
