import pytest

from ai_osop.core.targeted_permutator import TargetedPermutator


def test_targeted_permutator_php():
    # Test PHP technology mappings
    techs = ["WordPress", "PHP 8.1", "Laravel"]
    perms = TargetedPermutator.get_permutations(techs)

    assert "wp-config.php" in perms
    assert "wp-login.php" in perms
    assert "composer.json" in perms
    assert "artisan" in perms
    assert "manage.py" not in perms


def test_targeted_permutator_nextjs_and_django():
    # Test Next.js and Django technology mappings
    techs = ["Next.js", "Django", "Python"]
    perms = TargetedPermutator.get_permutations(techs)

    assert "manage.py" in perms
    assert "settings.py" in perms
    assert "_next/static/" in perms
    assert "next.config.js" in perms
    assert "wp-config.php" not in perms


def test_targeted_permutator_unknown_tech():
    # Test unknown or unmapped technologies return empty list
    techs = ["Apache", "Nginx", "UnknownTechStack"]
    perms = TargetedPermutator.get_permutations(techs)

    assert perms == []
