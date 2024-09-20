from asyncio import StreamReader, StreamWriter
import logging

LOGGER = logging.getLogger(__name__)

PACKET_SIZE_BYTES = 2


async def areceive(reader: StreamReader) -> bytes:
    """Application level read function. Reads the packet's length first, then read exactly the packet's size.
    asyncio version."""
    # wait for first packet giving payload size
    data = await reader.readexactly(PACKET_SIZE_BYTES)
    payload_size = int.from_bytes(data, byteorder="big")
    if payload_size == 0:
        LOGGER.debug("Empty packet received")
        return b""
    LOGGER.debug(f"Expecting next payload size of {payload_size} bytes")

    # return actual payload
    return await reader.readexactly(payload_size)


async def asend(writer: StreamWriter, data: bytes):
    """Application level write function. Sends the packet's length first, then the packet.
    asyncio version."""
    # pcbu's protocol requires to send the bytes length before the payload
    writer.write(len(data).to_bytes(PACKET_SIZE_BYTES, "big"))
    await writer.drain()

    # send the actual data
    writer.write(data)
    await writer.drain()
