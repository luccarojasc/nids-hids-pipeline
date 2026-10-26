import copy
import importlib.util
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location("s8", Path(__file__).resolve().parents[1]/"scripts/semana8_sensibilidade.py")
s8 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s8)

@pytest.mark.parametrize("seconds", [60,300,600])
def test_variation_only_window(seconds):
    core={"window_ns":300_000_000_000,"association_max_age_ns":300_000_000_000,"cases":[{"x":1}]}
    cfg={"window_ns":300_000_000_000,"critical_horizon_ns":300_000_000_000,"host_threshold":5,"network_threshold":10,"short_max_ns":5_000_000_000}
    old=copy.deepcopy((core,cfg))
    a,b=s8.variants(core,cfg,seconds)
    assert (core,cfg)==old
    assert a["window_ns"]==b["window_ns"]==seconds*1_000_000_000
    a["window_ns"]=b["window_ns"]=300_000_000_000
    assert (a,b)==old

@pytest.mark.parametrize("seconds", [0,120,True,60.0])
def test_invalid_grid(seconds):
    with pytest.raises(ValueError): s8.variants({}, {}, seconds)

def test_reject_changed_critical_horizon():
    with pytest.raises(ValueError):
        s8.variants({"window_ns":300_000_000_000}, {"window_ns":300_000_000_000,"critical_horizon_ns":60_000_000_000},60)
