-- metrics.user
SELECT
	COALESCE("status"::TEXT, 'unknown') AS "status",
	COUNT(*)::BIGINT AS "count"
FROM ${"schema"}.user
GROUP BY 1
ORDER BY 1;
