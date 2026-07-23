"""
Targeted Technology-Specific Permutator
Generates targeted wordlist extensions based on fingerprint technology categories.
"""

from typing import Dict, List, Set

# Framework directories and files footprints
FRAMEWORK_FOOTPRINTS: Dict[str, List[str]] = {
    "php": [
        "composer.json",
        "composer.lock",
        "wp-config.php",
        "index.php",
        "info.php",
        "phpinfo.php",
        "xmlrpc.php",
        "wp-admin/",
        "wp-content/",
        "wp-includes/",
        "artisan",
        ".env",
    ],
    "rails": [
        "Gemfile",
        "Gemfile.lock",
        "config/database.yml",
        "config/routes.rb",
        "config/environments/development.rb",
        "config/initializers/secret_token.rb",
        "db/seeds.rb",
        "public/packs/manifest.json",
        "rails/mailers",
    ],
    "django": [
        "manage.py",
        "wsgi.py",
        "asgi.py",
        "settings.py",
        "urls.py",
        "admin/",
        "static/",
        "media/",
        "requirements.txt",
        "pipfile",
    ],
    "node": [
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "node_modules/",
        "tsconfig.json",
        "webpack.config.js",
        ".env",
        ".npmrc",
    ],
    "nextjs": [
        "_next/static/",
        "_next/webpack-api/",
        "next.config.js",
        "pages/api/",
        "app/api/",
    ],
}

# Framework common administrative and high-risk paths
FRAMEWORK_ADMIN_PATHS: Dict[str, List[str]] = {
    "php": ["wp-login.php", "admin/", "administrator/", "install.php", "setup.php"],
    "rails": ["admin", "sidekiq", "rails/info/routes", "rails/info/properties"],
    "django": ["admin/", "admin/login/", "admin/password_change/"],
    "node": ["admin", "dashboard", "api/admin", "api/v1/admin"],
    "nextjs": ["api/auth/", "api/auth/signin", "api/auth/signout"],
}


class TargetedPermutator:
    """Generates targeted path candidates for directory fuzzing based on fingerprinted technologies."""

    @staticmethod
    def get_permutations(technologies: List[str]) -> List[str]:
        """Return a deduplicated list of framework-specific path candidates."""
        candidates: Set[str] = set()

        # Lowercase tech names for comparison
        techs_lower = [t.lower() for t in technologies]

        for tech in techs_lower:
            # Check for generic mappings or substrings (e.g. "laravel" / "wordpress" -> "php")
            framework_key = None
            if "php" in tech or "wordpress" in tech or "laravel" in tech:
                framework_key = "php"
            elif "rails" in tech or "ruby" in tech:
                framework_key = "rails"
            elif "django" in tech or "python" in tech:
                framework_key = "django"
            elif "node" in tech or "express" in tech or "koa" in tech:
                framework_key = "node"
            elif "next.js" in tech or "nextjs" in tech:
                framework_key = "nextjs"

            if framework_key:
                # Merge footprints and admin paths
                candidates.update(FRAMEWORK_FOOTPRINTS.get(framework_key, []))
                candidates.update(FRAMEWORK_ADMIN_PATHS.get(framework_key, []))

        return sorted(list(candidates))
