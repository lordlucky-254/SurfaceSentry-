from surfacesentry.plugins.manager import PluginManager
from surfacesentry.plugins.base import BasePlugin
from surfacesentry.core.models import Asset, Finding

class DummyPlugin(BasePlugin):
    name = "dummy"
    description = "Test plugin"

    def run(self, asset: Asset):
        return [Finding(
            plugin_name=self.name,
            severity="HIGH",
            title="Dummy Alert",
            description="Simulated vulnerability finding",
            target=asset.subdomain
        )]

def test_plugin_registration_and_execution():
    manager = PluginManager()
    dummy = DummyPlugin()
    manager.register_plugin(dummy)

    asset = Asset(subdomain="test.internal")
    findings = manager.run_all(asset)

    assert any(f.title == "Dummy Alert" for f in findings)
    assert any(f.severity == "HIGH" for f in findings)
