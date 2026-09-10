import sys
from pathlib import Path

# Ensure secp256k1lab is found and can be imported directly
sys.path.insert(0, str(Path(__file__).parent / "../src/"))
