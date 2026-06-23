"""GraphQL-specific vulnerability testing."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

INTROSPECTION_QUERY = """{
  __schema {
    types {
      name
      fields {
        name
        type { name kind ofType { name } }
      }
    }
    queryType { name }
    mutationType { name }
  }
}"""

DEPTH_QUERY_TEMPLATE = "{ __typename " + "".join(["{ __typename " for _ in range(20)]) + "}" * 20


class GraphQLModule(BaseTestModule):
    name = "graphql"
    category = "api"
    owasp_categories = ["A01", "A05"]
    description = "GraphQL vulnerability testing"

    def get_techniques(self) -> list[str]:
        return ["introspection", "depth_limit", "batch_attack", "field_suggestion"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []

        # Find GraphQL endpoints
        gql_endpoints = []
        for spec in session.discovered.api_specs:
            if spec.get("type") == "graphql":
                gql_endpoints.append(spec["url"])

        if not gql_endpoints:
            base_url = session.target.base_url
            for path in ["/graphql", "/graphiql", "/api/graphql", "/gql"]:
                try:
                    resp = await http.post(
                        f"{base_url}{path}",
                        json_data={"query": "{ __typename }"},
                        module="graphql",
                    )
                    if resp.status_code == 200 and "__typename" in resp.text:
                        gql_endpoints.append(f"{base_url}{path}")
                except Exception:
                    continue

        for url in gql_endpoints[:3]:
            # Test 1: Introspection
            try:
                resp = await http.post(url, json_data={"query": INTROSPECTION_QUERY}, module="graphql")
                if resp.status_code == 200 and "__schema" in resp.text:
                    data = resp.json()
                    types = data.get("data", {}).get("__schema", {}).get("types", [])
                    type_names = [t["name"] for t in types if not t["name"].startswith("__")]

                    findings.append(Finding(
                        title="GraphQL Introspection Enabled",
                        severity=Severity.MEDIUM,
                        category="misconfiguration",
                        owasp_category="A05",
                        description=f"GraphQL introspection is enabled, exposing the complete schema "
                                    f"({len(type_names)} types: {', '.join(type_names[:10])}...).",
                        remediation="Disable introspection in production. Only enable for development.",
                        endpoint=url,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cvss_score=5.3,
                        cwe_id="CWE-200",
                        evidence=[Evidence(
                            request_method="POST",
                            request_url=url,
                            response_status=resp.status_code,
                            description=f"Introspection returned {len(types)} types",
                        )],
                    ))
            except Exception:
                pass

            # Test 2: Query depth / complexity limit
            try:
                deep_query = "{ __typename " + "".join(["{ __typename " for _ in range(15)]) + "}" * 15
                resp = await http.post(url, json_data={"query": deep_query}, module="graphql")
                if resp.status_code == 200:
                    findings.append(Finding(
                        title="GraphQL No Query Depth Limit",
                        severity=Severity.MEDIUM,
                        category="misconfiguration",
                        owasp_category="A05",
                        description="No query depth limit detected. Deep/recursive queries can cause DoS.",
                        remediation="Implement query depth limiting (max 10-15 levels). "
                                    "Add query complexity analysis and cost limits.",
                        endpoint=url,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                        cvss_score=5.3,
                        cwe_id="CWE-400",
                    ))
            except Exception:
                pass

            # Test 3: Batch query attack
            try:
                batch = [{"query": "{ __typename }"} for _ in range(20)]
                resp = await http.post(url, json_data=batch, module="graphql")
                if resp.status_code == 200:
                    try:
                        result = resp.json()
                        if isinstance(result, list) and len(result) >= 20:
                            findings.append(Finding(
                                title="GraphQL Batch Query Not Limited",
                                severity=Severity.MEDIUM,
                                category="misconfiguration",
                                owasp_category="A05",
                                description="Server accepts batched GraphQL queries without limit. "
                                            "Can be used for brute force or DoS attacks.",
                                remediation="Limit the number of operations in a single batch request.",
                                endpoint=url,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                                cvss_score=5.3,
                                cwe_id="CWE-770",
                            ))
                    except Exception:
                        pass
            except Exception:
                pass

        return findings
