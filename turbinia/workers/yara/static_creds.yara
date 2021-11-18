rule TestRule
{
	strings:
		$ramoj_username = "ramoj_google_com"

	condition:
		$ramoj_username
}

rule TestRuleTwoYoDawg
{
	strings:
		$ramoj_username = "ramoj"

	condition:
		$ramoj_username
}
