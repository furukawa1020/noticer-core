import numpy as np

from noticer_core.data.synthetic import SyntheticConfig, generate_identity_dataset


def config() -> SyntheticConfig:
    return SyntheticConfig(5, 3, 12, 8, 3, 2.5, 0.4, 0.5, 1.0)


def test_synthetic_shape_metadata_and_reproducibility() -> None:
    first = generate_identity_dataset(config(), seed=42)
    second = generate_identity_dataset(config(), seed=42)
    different = generate_identity_dataset(config(), seed=43)
    assert np.array_equal(first.features, second.features)
    assert not np.array_equal(first.features, different.features)
    assert first.features.shape == (180, 8)
    assert len(first.metadata_frame()) == first.n_windows
    assert np.isfinite(first.features).all()
    assert set(first.metadata_frame().groupby("subject_id")["session_id"].nunique()) == {3}
