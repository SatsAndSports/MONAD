"""Test-only loopback admin route; all Cashu routes are unmodified upstream."""

import os

import uvicorn

from cashu.core.base import Unit
from cashu.mint.app import app
from cashu.mint.startup import ledger


@app.post("/_test/rotate")
async def rotate():
    await ledger.rotate_next_keyset(unit=Unit.sat, input_fee_ppk=0)
    return {"rotated": True}


if __name__ == "__main__":
    uvicorn.run(
        app, host="127.0.0.1", port=int(os.environ["MONAD_CHARACTERIZATION_PORT"])
    )
