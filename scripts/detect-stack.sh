#!/usr/bin/env bash
# detect-stack.sh - read-only reconnaissance of a repository's technology stack.
#
# Usage: detect-stack.sh [--json] [PATH]
#
# Looks only at file names and a few manifest files. It never executes project code,
# never installs anything and never writes to the repository.
# Output is a hint for the human or agent, not proof: always confirm by reading the code.
#
# Exit codes: 0 ok, 2 usage error / path problem.

set -u
set -o pipefail

JSON=0
ROOT=""
for arg in "$@"; do
  case "$arg" in
    --json) JSON=1 ;;
    -h|--help)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    -*) echo "detect-stack: unknown option: $arg" >&2; exit 2 ;;
    *)
      if [ -n "$ROOT" ]; then echo "detect-stack: only one PATH is accepted" >&2; exit 2; fi
      ROOT="$arg" ;;
  esac
done
ROOT="${ROOT:-.}"

if [ ! -d "$ROOT" ]; then
  echo "detect-stack: not a directory: $ROOT" >&2
  exit 2
fi
if [ ! -r "$ROOT" ]; then
  echo "detect-stack: directory is not readable: $ROOT" >&2
  exit 2
fi
ROOT="$(cd "$ROOT" && pwd)"

# Directories that are dependencies or build output, never first-party source.
PRUNE=( -name node_modules -o -name .git -o -name .next -o -name dist -o -name build -o -name vendor \
        -o -name .venv -o -name venv -o -name __pycache__ -o -name target -o -name .turbo -o -name coverage \
        -o -name .local-mongodb-data -o -name cms-media )

# find with a bounded depth so a huge monorepo cannot make this slow.
list_files() {
  find "$ROOT" -maxdepth 6 \( "${PRUNE[@]}" \) -prune -o -type f -print 2>/dev/null
}

FILES="$(list_files | head -n 20000)"
rel() { sed "s#^$ROOT/##"; }

has_file() { printf '%s\n' "$FILES" | grep -E -q "$1"; }
count_ext() { printf '%s\n' "$FILES" | grep -E -c "\.($1)$" || true; }
first_matches() { printf '%s\n' "$FILES" | grep -E "$1" | head -n "${2:-10}" | rel; }

# ---- languages (by extension, first-party files only) -----------------------
declare -a LANG_NAMES=("TypeScript" "JavaScript" "Python" "Go" "Java" "Kotlin" "Ruby" "PHP" "C#" "Rust" "Swift" "C/C++" "Shell" "SQL")
declare -a LANG_EXTS=("ts|tsx" "js|jsx|mjs|cjs" "py" "go" "java" "kt|kts" "rb" "php" "cs" "rs" "swift" "c|cc|cpp|h|hpp" "sh|bash" "sql")
LANG_OUT=()
for i in "${!LANG_NAMES[@]}"; do
  n="$(count_ext "${LANG_EXTS[$i]}")"
  [ "${n:-0}" -gt 0 ] && LANG_OUT+=("${LANG_NAMES[$i]}=$n")
done

# ---- package managers / manifests ------------------------------------------
MANIFESTS=()
add_manifest() { has_file "$1" && MANIFESTS+=("$2"); }
add_manifest '(^|/)package\.json$' "npm-package.json"
add_manifest '(^|/)pnpm-lock\.yaml$' "pnpm-lock.yaml"
add_manifest '(^|/)package-lock\.json$' "package-lock.json"
add_manifest '(^|/)yarn\.lock$' "yarn.lock"
add_manifest '(^|/)bun\.lockb?$' "bun.lock"
add_manifest '(^|/)requirements[^/]*\.txt$' "pip-requirements"
add_manifest '(^|/)pyproject\.toml$' "pyproject.toml"
add_manifest '(^|/)Pipfile(\.lock)?$' "Pipfile"
add_manifest '(^|/)poetry\.lock$' "poetry.lock"
add_manifest '(^|/)go\.(mod|sum)$' "go.mod"
add_manifest '(^|/)Cargo\.(toml|lock)$' "Cargo"
add_manifest '(^|/)pom\.xml$' "maven-pom"
add_manifest '(^|/)build\.gradle(\.kts)?$' "gradle"
add_manifest '(^|/)Gemfile(\.lock)?$' "Gemfile"
add_manifest '(^|/)composer\.(json|lock)$' "composer"
add_manifest '(^|/)[^/]+\.csproj$' "dotnet-csproj"

# ---- frameworks (best effort, from dependency names in manifests) ------------
FRAMEWORKS=()
MANIFEST_FILES="$(printf '%s\n' "$FILES" | grep -E '(^|/)(package\.json|requirements[^/]*\.txt|pyproject\.toml|go\.mod|Gemfile|composer\.json|pom\.xml)$' | head -n 30)"
dep_hint() { # $1 regex over manifest text, $2 label. Reads line by line so paths containing spaces work.
  local f
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if grep -E -q "$1" "$f" 2>/dev/null; then FRAMEWORKS+=("$2"); return; fi
  done <<<"$MANIFEST_FILES"
}
dep_hint '"next"[[:space:]]*:' "Next.js"
dep_hint '"react"[[:space:]]*:' "React"
dep_hint '"express"[[:space:]]*:' "Express"
dep_hint '"fastify"[[:space:]]*:' "Fastify"
dep_hint '"@nestjs/core"' "NestJS"
dep_hint '"payload"[[:space:]]*:' "Payload CMS"
dep_hint '"mongoose"[[:space:]]*:' "Mongoose/MongoDB"
dep_hint '"(prisma|@prisma/client)"' "Prisma"
dep_hint '"(pg|mysql2|sequelize|typeorm|knex)"' "SQL driver/ORM"
dep_hint '"(jsonwebtoken|jose)"' "JWT library"
dep_hint '"(next-auth|@auth/core|passport|lucia)"' "Auth library"
dep_hint '"(bullmq|amqplib|kafkajs)"' "Queue/broker client"
dep_hint '"(openai|@anthropic-ai/sdk|langchain|ai)"[[:space:]]*:' "LLM SDK"
dep_hint '(^|[^a-z])django([^a-z]|$)' "Django"
dep_hint '(^|[^a-z])flask([^a-z]|$)' "Flask"
dep_hint '(^|[^a-z])fastapi([^a-z]|$)' "FastAPI"
dep_hint 'gin-gonic/gin|labstack/echo|gofiber' "Go web framework"
dep_hint 'rails' "Rails"
dep_hint 'laravel/framework' "Laravel"
dep_hint 'spring-boot' "Spring Boot"

# ---- infrastructure, CI, security docs, entry points -------------------------
INFRA="$(first_matches '(^|/)(Dockerfile[^/]*|docker-compose[^/]*\.ya?ml|compose\.ya?ml|nginx[^/]*\.conf|ecosystem\.config\.[a-z]+|vercel\.json|netlify\.toml|fly\.toml|serverless\.ya?ml|Procfile|[^/]+\.tf|helm/.+|k8s/.+|kubernetes/.+)$' 15)"
CI="$(first_matches '(^|/)(\.github/workflows/[^/]+|\.gitlab-ci\.yml|azure-pipelines\.yml|\.circleci/config\.yml|Jenkinsfile|buildkite[^/]*)$' 10)"
SECDOCS="$(first_matches '(^|/)(SECURITY(\.md)?|security\.txt|THREAT[-_]?MODEL[^/]*|docs/[^/]*security[^/]*)$' 10)"
ENVFILES="$(first_matches '(^|/)\.env(\.[A-Za-z0-9_-]+)?$' 10)"
ROUTES="$(first_matches '(^|/)(app/.*/route\.(ts|js)|pages/api/.+|src/routes?/.+|routes?/.+\.(js|ts|py|rb|php)|.+\.routes?\.(js|ts)|.+controllers?/.+|api/.+\.(js|ts|py))$' 15)"
AUTHFILES="$(first_matches '(auth|login|session|jwt|rbac|permission|access|middleware|proxy|csrf|cors)[^/]*\.(ts|tsx|js|mjs|py|go|rb|php|java|cs)$' 15)"
UPLOADS="$(first_matches '(upload|multer|storage|media)[^/]*\.(ts|tsx|js|mjs|py|go|rb|php|java|cs)$' 8)"
TESTS="$(first_matches '(^|/)(tests?|__tests__|spec|e2e)/.+' 8)"
ENV_TRACKED_WARN=""
if [ -d "$ROOT/.git" ] && command -v git >/dev/null 2>&1; then
  tracked="$(git -C "$ROOT" ls-files -- '.env' '.env.*' 2>/dev/null | grep -v -E '\.(example|sample|template)$' | head -n 5)"
  [ -n "$tracked" ] && ENV_TRACKED_WARN="$tracked"
fi

join_json() { # prints a JSON array of strings from stdin lines
  local first=1 line esc
  printf '['
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    esc="${line//\\/\\\\}"; esc="${esc//\"/\\\"}"
    [ $first -eq 0 ] && printf ','
    printf '"%s"' "$esc"; first=0
  done
  printf ']'
}

if [ "$JSON" -eq 1 ]; then
  printf '{"root":"%s","languages":%s,"manifests":%s,"frameworks":%s,' \
    "${ROOT//\"/\\\"}" \
    "$(printf '%s\n' "${LANG_OUT[@]:-}" | join_json)" \
    "$(printf '%s\n' "${MANIFESTS[@]:-}" | join_json)" \
    "$(printf '%s\n' "${FRAMEWORKS[@]:-}" | sort -u | join_json)"
  printf '"infrastructure":%s,"ci":%s,"securityDocs":%s,"envFiles":%s,"trackedEnvFiles":%s,"routeFiles":%s,"securityRelevantFiles":%s,"uploadRelatedFiles":%s,"testFiles":%s,' \
    "$(printf '%s\n' "$INFRA" | join_json)" "$(printf '%s\n' "$CI" | join_json)" "$(printf '%s\n' "$SECDOCS" | join_json)" \
    "$(printf '%s\n' "$ENVFILES" | join_json)" "$(printf '%s\n' "$ENV_TRACKED_WARN" | join_json)" "$(printf '%s\n' "$ROUTES" | join_json)" \
    "$(printf '%s\n' "$AUTHFILES" | join_json)" "$(printf '%s\n' "$UPLOADS" | join_json)" "$(printf '%s\n' "$TESTS" | join_json)"
  printf '"note":"heuristic file-name based hints; confirm by reading the code"}\n'
  exit 0
fi

show() { # $1 title, $2 content
  printf '\n## %s\n' "$1"
  if [ -n "$2" ]; then printf '%s\n' "$2" | sed 's/^/- /'; else echo "- (none found)"; fi
}

echo "# Stack detection for: $ROOT"
echo "(heuristic, file-name based. Confirm everything by reading the code.)"
show "Languages (first-party file counts)" "$(printf '%s\n' "${LANG_OUT[@]:-}")"
show "Manifests and lockfiles" "$(printf '%s\n' "${MANIFESTS[@]:-}")"
show "Framework hints (from dependency names)" "$(printf '%s\n' "${FRAMEWORKS[@]:-}" | sort -u)"
show "Infrastructure and deployment files" "$INFRA"
show "CI configuration" "$CI"
show "Existing security documentation" "$SECDOCS"
show "Route and API entry-point files" "$ROUTES"
show "Authentication, session, access-control and middleware files" "$AUTHFILES"
show "Upload and media related files" "$UPLOADS"
show "Environment files present (contents are NOT read)" "$ENVFILES"
if [ -n "$ENV_TRACKED_WARN" ]; then
  show "WARNING: environment files tracked by git (investigate; contents not read)" "$ENV_TRACKED_WARN"
fi
show "Test directories/files" "$TESTS"
if [ "${#LANG_OUT[@]}" -eq 0 ] && [ "${#MANIFESTS[@]}" -eq 0 ]; then
  echo
  echo "NOTE: no recognised source files or manifests were found. Is PATH the repository root?"
fi
exit 0
