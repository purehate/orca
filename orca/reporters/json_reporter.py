"""JSON reporter for ORCA."""

from orca.findings import ScanResult


class JSONReporter:
    def generate(self, result: ScanResult) -> str:
        return result.to_json(indent=2)

    def save(self, result: ScanResult, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.generate(result))
