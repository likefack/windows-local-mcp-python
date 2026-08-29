from pathlib import Path

path = Path("tests/test_tunnel_integration.py")
text = path.read_text(encoding="utf-8")
path.write_text(text.rstrip() + "\n", encoding="utf-8")
print("normalized test EOF")
