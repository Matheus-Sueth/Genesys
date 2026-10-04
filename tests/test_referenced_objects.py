import tempfile
import unittest
from pathlib import Path

import yaml

from genesys.archy import FileYaml


NEW_ARCHY_INBOUND_CALL = """inboundCall:
  name: Referenced Objects Test
  division: Home
  startUpRef: /inboundCall/tasks/task[Main_1]
  initialGreeting: {}
  defaultLanguage: pt-br
  supportedLanguages: {}
  settingsActionDefaults: {}
  settingsErrorHandling: {}
  settingsMenu: {}
  settingsPrompts: {}
  settingsSpeechRec: {}
  tasks:
    - task:
        name: Main
        refId: Main_1
        actions:
          - callCommonModule:
              name: Common module
              commonModule:
                CM - Teste:
                  ver_latestPublished: {}
          - transferToFlow:
              name: Transfer
              targetFlow:
                name: Fluxo Secundario
  referencedObjects:
    flows:
      - flow:
          name: CM - Teste
          type: commonmodule
          defaultLanguage: pt-br
          variables:
            - jsonVariable:
                name: Common.changes
                isInput: true
                isOutput: false
            - decimalVariable:
                name: Common.valor
                isInput: false
                isOutput: true
          supportedLanguages:
            - pt-br
          compatibleFlowTypes:
            - inboundcall
"""


class ReferencedObjectsTests(unittest.TestCase):
    def _write_yaml(self, directory: str, content: str, name: str = "flow.yaml") -> Path:
        path = Path(directory) / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_parses_and_preserves_referenced_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self._write_yaml(directory, NEW_ARCHY_INBOUND_CALL)
            parsed = FileYaml(str(source))

            referenced = parsed.flow.referencedObjects
            flow = referenced["flows"][0]["flow"]
            self.assertEqual(flow["name"], "CM - Teste")
            self.assertEqual(
                flow["variables"][0]["jsonVariable"]["name"],
                "Common.changes",
            )

            self.assertEqual(
                parsed.flow.get_dependencies("flows"),
                [
                    ("CM - Teste", "commonModule"),
                    ("Fluxo Secundario", "inboundcall"),
                ],
            )

            output = Path(directory) / "roundtrip.yaml"
            parsed.save_yaml_to_file(str(output))
            saved = yaml.safe_load(output.read_text(encoding="utf-8"))
            self.assertEqual(
                saved["inboundCall"]["referencedObjects"],
                referenced,
            )

    def test_rejects_yaml_without_referenced_objects(self):
        legacy = NEW_ARCHY_INBOUND_CALL.replace(
            """  referencedObjects:
    flows:
      - flow:
          name: CM - Teste
          type: commonmodule
          defaultLanguage: pt-br
          variables:
            - jsonVariable:
                name: Common.changes
                isInput: true
                isOutput: false
            - decimalVariable:
                name: Common.valor
                isInput: false
                isOutput: true
          supportedLanguages:
            - pt-br
          compatibleFlowTypes:
            - inboundcall
""",
            "",
        )
        with tempfile.TemporaryDirectory() as directory:
            source = self._write_yaml(directory, legacy)
            with self.assertRaisesRegex(ValueError, "referencedObjects"):
                FileYaml(str(source))


if __name__ == "__main__":
    unittest.main()
