"""Create local Compose credentials once; never overwrite an existing instance password."""
from pathlib import Path
import secrets

path = Path(__file__).resolve().parent / '.env'
try:
    with path.open('x', encoding='utf-8') as stream:
        stream.write('DAGSTER_POSTGRES_PASSWORD=' + secrets.token_hex(32) + '\n')
    print('Created ignored local Compose configuration.')
except FileExistsError:
    print('Existing local Compose configuration preserved.')
