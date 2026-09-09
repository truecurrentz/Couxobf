import re

from couxobf.names import make_name_generator
from couxobf.rng import Rng, coerce_seed
from couxobf.lower_back import helper_names, helpers_src

IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _rng(seed, domain="identifiers"):
    return Rng(coerce_seed(seed), domain)


def test_identifier_generator_uses_multiple_build_families_without_leaks():
    families = set()
    samples_by_seed = []
    for seed in range(1, 24):
        gen = make_name_generator(_rng(seed), reserved={"taken"})
        names = gen.fresh_many(80)
        families.add(gen.family)
        assert len(names) == len(set(names))
        assert "taken" not in names
        assert all(IDENT_RE.match(name) for name in names)
        assert all(3 <= len(name) <= 8 for name in names)
        assert not any("health" in name or "player" in name for name in names)
        samples_by_seed.append(tuple(names[:12]))

    assert len(families) >= 3
    assert len(set(samples_by_seed)) == len(samples_by_seed)


def test_helper_implementations_polymorph_between_builds():
    layouts = set()
    for seed in range(1, 10):
        h = helper_names(_rng(seed, "helpers"))
        src = helpers_src(h)
        layouts.add(("table.pack" in src,
                     "select(\"#\",...)" in src,
                     "while i <= t.n" in src,
                     "dst[n + i]" in src))
    assert len(layouts) >= 3
