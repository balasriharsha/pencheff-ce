// SupportedKind — wire-value enum for Target.kind. The 3 legacy values are
// preserved indefinitely (existing rows + API backwards-compat); the 12 new
// values land with feature 001-multi-target-scan-pipelines. Snake_case matches
// the Pydantic Literal at apps/api/pencheff_api/schemas/targets.py::TargetKind.
//
// FE type-card IDs (kebab-case) are mapped to wire kinds (snake_case) per the
// spec 10.1 normative table — see CATEGORIES below.
export type SupportedKind =
  | "url"
  | "repo"
  | "llm" // legacy — preserved on the wire indefinitely
  | "web_app"
  | "rest_api"
  | "graphql"
  | "websocket"
  | "grpc"
  | "source_code"
  | "cicd_pipeline"
  | "iac"
  | "container_image"
  | "k8s_cluster"
  | "package_registry"
  | "sbom"
  | "cloud_account"
  | "serverless_function"
  | "cloud_storage"
  | "load_balancer_cdn"
  | "cloud_database"
  | "secrets_manager"
  | "host" // sub-project A
  | "memory" // agent memory / vector-store, scanned via the memory scanner
  | "mcp" // Model Context Protocol servers & agents
  | "rag" // Retrieval-Augmented Generation / vector databases
  | "ml_model" // ML model artifact — static no-load scanning
  | "voice"; // Voice / Speech-AI — STT/TTS/voice-bot/voice-auth
export type TypeStatus = "active" | "coming-soon";

export type TargetType = {
  id: string;
  num: number;
  label: string;
  description: string;
  kind: SupportedKind | null;
  status: TypeStatus;
  categoryId: string;
};

export type TargetCategory = {
  id: string;
  label: string;
  types: TargetType[];
};

export const CATEGORIES: TargetCategory[] = [
  {
    id: "web-api",
    label: "Web & API Security",
    types: [
      {
        id: "web-app",
        num: 1,
        label: "Web Application (URL)",
        description: "DAST, OWASP Top 10, auth flows, misconfigurations",
        kind: "web_app",
        status: "active",
        categoryId: "web-api",
      },
      {
        id: "rest-api",
        num: 2,
        label: "REST API",
        description: "RESTful APIs, endpoints, auth, fuzzing",
        kind: "rest_api",
        status: "active",
        categoryId: "web-api",
      },
      {
        id: "graphql-api",
        num: 3,
        label: "GraphQL API",
        description: "GraphQL endpoints, queries, introspection, BOLA",
        kind: "graphql",
        status: "active",
        categoryId: "web-api",
      },
      {
        id: "websocket",
        num: 4,
        label: "WebSocket",
        description: "Real-time endpoints, messaging, auth",
        kind: "websocket",
        status: "active",
        categoryId: "web-api",
      },
      {
        id: "grpc",
        num: 5,
        label: "gRPC Service",
        description: "gRPC endpoints, protobuf validation, auth",
        kind: "grpc",
        status: "active",
        categoryId: "web-api",
      },
    ],
  },
  {
    id: "code-supply",
    label: "Code & Supply Chain Security",
    types: [
      {
        id: "source-code-repo",
        num: 6,
        label: "Source Code Repository",
        description: "GitHub, GitLab, Bitbucket SAST, secrets, SCA",
        kind: "source_code",
        status: "active",
        categoryId: "code-supply",
      },
      {
        id: "cicd-pipeline",
        num: 7,
        label: "CI/CD Pipeline",
        description: "Jenkins, GitHub Actions, GitLab CI, Azure DevOps",
        kind: "cicd_pipeline",
        status: "active",
        categoryId: "code-supply",
      },
      {
        id: "iac",
        num: 8,
        label: "IaC (Infrastructure as Code)",
        description: "Terraform, CloudFormation, Pulumi, ARM, CDK",
        kind: "iac",
        status: "active",
        categoryId: "code-supply",
      },
      {
        id: "container-image",
        num: 9,
        label: "Container Image",
        description: "Docker images, layers, CVE, misconfigurations",
        kind: "container_image",
        status: "active",
        categoryId: "code-supply",
      },
      {
        id: "kubernetes",
        num: 10,
        label: "Kubernetes Cluster",
        description: "K8s cluster, workloads, RBAC, network policies",
        kind: "k8s_cluster",
        status: "active",
        categoryId: "code-supply",
      },
      {
        id: "package-registry",
        num: 11,
        label: "Package Registry",
        description: "npm, PyPI, Maven, NuGet malicious packages",
        kind: "package_registry",
        status: "active",
        categoryId: "code-supply",
      },
      {
        id: "sbom-deps",
        num: 12,
        label: "SBOM / Dependencies",
        description: "Software Bill of Materials, dependency risk",
        kind: "sbom",
        status: "active",
        categoryId: "code-supply",
      },
    ],
  },
  {
    id: "infra-cloud",
    label: "Infrastructure & Cloud Security",
    types: [
      {
        id: "cloud-account",
        num: 13,
        label: "Cloud Account (CSPM)",
        description: "AWS, Azure, GCP configurations, IAM, risks",
        kind: "cloud_account",
        status: "active",
        categoryId: "infra-cloud",
      },
      {
        id: "serverless",
        num: 14,
        label: "Serverless Functions",
        description: "AWS Lambda, Azure Func, GCP Cloud Functions",
        kind: "serverless_function",
        status: "active",
        categoryId: "infra-cloud",
      },
      {
        id: "cloud-storage",
        num: 15,
        label: "Cloud Storage",
        description: "S3, Blob, GCS, buckets, blobs, permissions",
        kind: "cloud_storage",
        status: "active",
        categoryId: "infra-cloud",
      },
      {
        id: "load-balancer-cdn",
        num: 16,
        label: "Load Balancer / CDN",
        description: "ELB, ALB, CloudFront, Akamai, Fastly",
        kind: "load_balancer_cdn",
        status: "active",
        categoryId: "infra-cloud",
      },
      {
        id: "database-cloud",
        num: 17,
        label: "Database (Cloud)",
        description: "RDS, Cloud SQL, Cosmos DB, security & access",
        kind: "cloud_database",
        status: "active",
        categoryId: "infra-cloud",
      },
      {
        id: "secrets-manager",
        num: 18,
        label: "Secrets Manager",
        description: "AWS Secrets, Azure Key Vault, GCP Secret Manager",
        kind: "secrets_manager",
        status: "active",
        categoryId: "infra-cloud",
      },
    ],
  },
  {
    id: "network-host",
    label: "Network & Host Security",
    types: [
      {
        id: "network-host",
        num: 19,
        label: "Network Host / IP",
        description:
          "Open ports, services, OS detection, vulns (FQDN or IP). OS-level exploitation ships in sub-project B.",
        kind: "host",
        status: "active",
        categoryId: "network-host",
      },
      {
        id: "tls-ssl",
        num: 20,
        label: "TLS/SSL Configuration",
        description: "Certificate, ciphers, TLS hardening, SSL Labs",
        kind: null,
        status: "coming-soon",
        categoryId: "network-host",
      },
      {
        id: "dns-subdomain",
        num: 21,
        label: "DNS & Subdomain",
        description: "DNS records, zone transfer, subdomain enumeration",
        kind: null,
        status: "coming-soon",
        categoryId: "network-host",
      },
      {
        id: "email-security",
        num: 22,
        label: "Email Security",
        description: "SPF, DKIM, DMARC, phishing, spoofing",
        kind: null,
        status: "coming-soon",
        categoryId: "network-host",
      },
      {
        id: "vpn-remote",
        num: 23,
        label: "VPN / Remote Access",
        description: "VPN gateways, RDP, SSH, exposed services",
        kind: null,
        status: "coming-soon",
        categoryId: "network-host",
      },
      {
        id: "internal-network",
        num: 24,
        label: "Internal Network",
        description: "Lateral movement, SMB, RDP, internal assets",
        kind: null,
        status: "coming-soon",
        categoryId: "network-host",
      },
    ],
  },
  {
    id: "ai-llm",
    label: "AI & LLM Security",
    types: [
      {
        id: "llm-endpoint",
        num: 25,
        label: "LLM Endpoint",
        description: "Chat endpoints, prompt injection, red-team",
        kind: "llm",
        status: "active",
        categoryId: "ai-llm",
      },
      {
        id: "mcp-ai-agents",
        num: 26,
        label: "MCP / AI Agents",
        description: "Model Context Protocol servers & agents",
        kind: "mcp",
        status: "active",
        categoryId: "ai-llm",
      },
      {
        id: "rag-vector-db",
        num: 27,
        label: "RAG / Vector DB",
        description: "Retrieval systems, vector DB poisoning, leakage",
        kind: "rag",
        status: "active",
        categoryId: "ai-llm",
      },
      {
        id: "ml-model",
        num: 28,
        label: "ML Model / Pipeline",
        description: "ML models, training data, poisoning, inference",
        kind: "ml_model",
        status: "active",
        categoryId: "ai-llm",
      },
      {
        id: "voice-speech-ai",
        num: 29,
        label: "Voice / Speech AI",
        description: "Voice bots, STT/TTS, auth, template-based probes",
        kind: "voice",
        status: "active",
        categoryId: "ai-llm",
      },
      {
        id: "agent-memory",
        num: 30,
        label: "Agent Memory / Vector Store",
        description:
          "Paste, upload, or register provider memory for secrets + poisoning",
        kind: "memory",
        status: "active",
        categoryId: "ai-llm",
      },
    ],
  },
  {
    id: "mobile-client",
    label: "Mobile & Client Security",
    types: [
      {
        id: "android-app",
        num: 31,
        label: "Android Application",
        description: "APK analysis, malware, secrets, cert pinning",
        kind: null,
        status: "coming-soon",
        categoryId: "mobile-client",
      },
      {
        id: "ios-app",
        num: 32,
        label: "iOS Application",
        description: "IPA analysis, security, crypto, storage",
        kind: null,
        status: "coming-soon",
        categoryId: "mobile-client",
      },
      {
        id: "browser-extension",
        num: 33,
        label: "Browser Extension",
        description: "Chrome, Firefox, Edge extensions",
        kind: null,
        status: "coming-soon",
        categoryId: "mobile-client",
      },
      {
        id: "desktop-app",
        num: 34,
        label: "Desktop Application",
        description: "Electron, Java, .NET, Qt applications",
        kind: null,
        status: "coming-soon",
        categoryId: "mobile-client",
      },
    ],
  },
  {
    id: "ot-iot",
    label: "OT / IoT & Hardware Security",
    types: [
      {
        id: "firmware",
        num: 35,
        label: "Firmware / Embedded",
        description: "Firmware analysis, reverse engineering, CVE",
        kind: null,
        status: "coming-soon",
        categoryId: "ot-iot",
      },
      {
        id: "iot-device",
        num: 36,
        label: "IoT Device",
        description: "IoT devices, firmware, misconfigurations",
        kind: null,
        status: "coming-soon",
        categoryId: "ot-iot",
      },
      {
        id: "ot-ics-scada",
        num: 37,
        label: "OT / ICS / SCADA",
        description: "Industrial systems, PLC, SCADA, HMI",
        kind: null,
        status: "coming-soon",
        categoryId: "ot-iot",
      },
    ],
  },
  {
    id: "identity-compliance",
    label: "Identity, Data & Compliance",
    types: [
      {
        id: "identity-provider",
        num: 38,
        label: "Identity Provider (IdP)",
        description: "Okta, Azure AD, Auth0, SSO, OAuth, SAML",
        kind: null,
        status: "coming-soon",
        categoryId: "identity-compliance",
      },
      {
        id: "database-store",
        num: 39,
        label: "Database / Data Store",
        description: "MySQL, PostgreSQL, MongoDB, Redis, etc.",
        kind: null,
        status: "coming-soon",
        categoryId: "identity-compliance",
      },
      {
        id: "compliance-posture",
        num: 40,
        label: "Compliance Posture",
        description: "SOC 2, ISO 27001, PCI-DSS, HIPAA, GDPR, NIST",
        kind: null,
        status: "coming-soon",
        categoryId: "identity-compliance",
      },
    ],
  },
];

export const TYPES_BY_ID: Record<string, TargetType> = Object.fromEntries(
  CATEGORIES.flatMap((c) => c.types).map((t) => [t.id, t]),
);

// IDs of all active (non-coming-soon) types — used for "Select All"
export const SELECT_ALL_IDS: string[] = CATEGORIES.flatMap((c) =>
  c.types.filter((t) => t.status === "active").map((t) => t.id),
);
