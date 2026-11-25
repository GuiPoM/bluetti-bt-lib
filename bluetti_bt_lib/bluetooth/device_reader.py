import asyncio
import logging
import async_timeout
from typing import Any, Callable, List, cast
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError
from bleak_retry_connector import (
    BleakClientWithServiceCache,
    _get_properties,
    clear_cache,
    establish_connection,
    path_from_ble_device,
)

from .encryption import BluettiEncryption, Message, MessageType, AES_BLOCK_SIZE
from ..base_devices import BluettiDevice
from ..const import ALTERNATE_NOTIFY_UUID, NOTIFY_UUID, WRITE_UUID
from ..registers import ReadableRegisters, DeviceRegister
from ..utils.privacy import mac_loggable


class DeviceReaderConfig:
    def __init__(self, timeout: int = 60, use_encryption: bool = False):
        self.timeout = timeout
        self.use_encryption = use_encryption


class DeviceReader:
    def __init__(
        self,
        mac: str,
        bluetti_device: BluettiDevice,
        future_builder_method: Callable[[], asyncio.Future[Any]],
        config: DeviceReaderConfig = DeviceReaderConfig(),
        lock: asyncio.Lock = asyncio.Lock(),
        ble_client: BleakClient | None = None,
    ):
        self.mac = mac
        self.bluetti_device = bluetti_device
        self.create_future = future_builder_method
        self.config = config
        self.polling_lock = lock

        self.ble_client = ble_client
        """Used for unittests"""

        self.logger = logging.getLogger(
            f"{__name__}.{mac_loggable(mac).replace(':', '_')}"
        )

        self.device = None
        self.client = None

        self.has_notifier = False
        self.current_registers = None
        self.notify_response = bytearray()
        self.notify_future: asyncio.Future[Any] | None = None
        self.encryption = BluettiEncryption()
        self.encrypted_buffer = bytearray()

    async def read(
        self, only_registers: List[ReadableRegisters] | None = None, raw: bool = False
    ) -> dict | None:

        registers = self.bluetti_device.get_polling_registers()
        pack_registers = self.bluetti_device.get_pack_polling_registers()

        if only_registers is not None:
            registers = only_registers
            pack_registers = []

        parsed_data: dict = {}

        self.logger.debug("Reading device registers")

        async with self.polling_lock:
            try:
                async with async_timeout.timeout(self.config.timeout):
                    self.logger.debug("Searching for device")

                    if self.ble_client:
                        self.device = None
                    else:
                        self.device = await BleakScanner.find_device_by_address(
                            self.mac, timeout=5
                        )

                        if self.device is None:
                            self.logger.error("Device not found")
                            return

                    self.logger.debug("Connecting to device")

                    if self.ble_client:
                        self.client = self.ble_client
                    else:
                        self.client = await establish_connection(
                            BleakClientWithServiceCache,
                            self.device,
                            self.device.name or "Unknown Device",
                            max_attempts=10,
                            use_services_cache=False,
                        )

                    self.logger.debug("Connected to device")

                    backend = getattr(self.client, "_backend", None)
                    device_path = path_from_ble_device(self.device)
                    self.logger.warning(
                        "BLE backend=%s device_path=%s client_path=%s",
                        type(backend).__name__,
                        device_path,
                        getattr(backend, "_device_path", None),
                    )
                    if device_path:
                        try:
                            properties = await _get_properties()
                            service_paths = [
                                path
                                for path, interfaces in properties.items()
                                if path.startswith(device_path + "/")
                                and any(
                                    "GattService1" in interface
                                    for interface in interfaces
                                )
                            ]
                            self.logger.warning(
                                "BlueZ D-Bus GattService1 objects: %d (%s)",
                                len(service_paths),
                                ", ".join(service_paths),
                            )
                        except Exception:
                            self.logger.warning(
                                "Unable to inspect BlueZ GATT objects", exc_info=True
                            )

                    try:
                        services = self.client.services
                    except BleakError as err:
                        self.logger.warning(
                            "GATT services not ready after connect: %s", err
                        )
                        services = None
                    service_map = getattr(services, "services", {})
                    if not service_map and not self.ble_client:
                        await asyncio.sleep(2)
                        backend = getattr(self.client, "_backend", None)
                        refresh_services = getattr(backend, "_get_services", None)
                        if refresh_services is not None:
                            try:
                                await refresh_services(
                                    dangerous_use_bleak_cache=False
                                )
                            except Exception as err:
                                self.logger.warning(
                                    "Bleak service refresh failed: %s",
                                    repr(err),
                                    exc_info=True,
                                )
                            try:
                                services = self.client.services
                            except BleakError:
                                services = None
                            service_map = getattr(services, "services", {})
                    if not service_map and not self.ble_client:
                        self.logger.warning(
                            "BlueZ returned no GATT services; reconnecting for fresh discovery"
                        )
                        await self.client.disconnect()
                        try:
                            cache_cleared = await clear_cache(self.mac)
                            self.logger.warning(
                                "BlueZ service cache cleared: %s", cache_cleared
                            )
                        except Exception:
                            self.logger.warning(
                                "Unable to clear BlueZ service cache", exc_info=True
                            )
                        await asyncio.sleep(1)
                        self.device = await BleakScanner.find_device_by_address(
                            self.mac, timeout=10
                        )
                        if self.device is None:
                            raise BleakError("Device disappeared after BlueZ cache clear")
                        self.client = await establish_connection(
                            BleakClientWithServiceCache,
                            self.device,
                            self.device.name or "Unknown Device",
                            max_attempts=3,
                            use_services_cache=False,
                        )
                        services = getattr(self.client, "services", None)
                        service_map = getattr(services, "services", {})
                    self.logger.warning(
                        "GATT discovery: %d services (%s)",
                        len(service_map),
                        ", ".join(str(uuid) for uuid in service_map),
                    )

                    if not self.has_notifier:
                        try:
                            await self.client.start_notify(
                                NOTIFY_UUID, self._notification_handler
                            )
                        except BleakError as err:
                            # Some newer BLUETTI firmware exposes the data
                            # notification characteristic as FF03 instead of
                            # FF01.  Keep FF01 as the normal path and fall
                            # back only when the characteristic is absent.
                            if "ff01" not in str(err).lower():
                                raise
                            self.logger.warning(
                                "FF01 notification characteristic unavailable; trying FF03"
                            )
                            await self.client.start_notify(
                                ALTERNATE_NOTIFY_UUID, self._notification_handler
                            )
                        self.has_notifier = True

                    self.logger.debug("Notification handler setup complete")

                    while (
                        self.config.use_encryption
                        and not self.encryption.is_ready_for_commands
                    ):
                        await asyncio.sleep(5)
                        self.logger.debug("Encryption handshake not finished yet")

                    for register in registers:
                        body = register.parse_response(
                            await self._async_send_command(register)
                        )

                        self.logger.debug("Raw data: %s", body)

                        if raw:
                            d = {}
                            d[register.starting_address] = body
                            parsed_data.update(d)
                            continue

                        parsed = self.bluetti_device.parse(
                            register.starting_address, body
                        )

                        self.logger.debug("Parsed data: %s", parsed)

                        parsed_data.update(parsed)

                    for pack in range(1, self.bluetti_device.max_packs + 1):
                        body = register.parse_response(
                            await self._async_send_command(
                                self.bluetti_device.get_pack_selector(pack),
                            )
                        )

                        # We need to wait for the powerstation to populate all registers
                        await asyncio.sleep(3)

                        for register in pack_registers:
                            body = register.parse_response(
                                await self._async_send_command(register)
                            )

                            self.logger.debug("Raw data: %s", body)

                            if raw:
                                d = {}
                                d[register.starting_address] = body
                                parsed_data.update(d)
                                continue

                            parsed = self.bluetti_device.parse(
                                register.starting_address,
                                body,
                                pack_num=pack,
                            )

                            self.logger.debug("Parsed data: %s", parsed)

                            parsed_data.update(parsed)

            except TimeoutError:
                self.logger.warning("Timeout")
                return None
            except BleakError as err:
                self.logger.warning("Bleak error: %s", err)
                return None
            except BaseException as err:
                self.logger.warning("Unknown error %s", err)
                return None
            finally:
                if self.has_notifier:
                    try:
                        await self.client.stop_notify(NOTIFY_UUID)
                        self.logger.debug("Stopped notifier")
                    except:
                        # Ignore errors here
                        pass
                    self.has_notifier = False
                if self.client:
                    await self.client.disconnect()
                    self.logger.debug("Disconnected from device")

            # Reset Encryption keys
            self.encryption.reset()
            self.encrypted_buffer.clear()

            # Check if dict is empty
            if not parsed_data:
                return None

            return parsed_data

    async def _async_send_command(self, registers: DeviceRegister) -> bytes:
        """Send command and return response"""
        self.current_registers = registers
        self.notify_response = bytearray()
        self.notify_future = self.create_future()
        self.encrypted_buffer.clear()

        command_bytes = bytes(registers)

        # Encrypt command
        if self.config.use_encryption is True:
            if not self.encryption.is_ready_for_commands:
                return bytes()
            command_bytes = self.encryption.aes_encrypt(
                command_bytes, self.encryption.secure_aes_key, None
            )

        try:
            # Make request
            await self.client.write_gatt_char(WRITE_UUID, command_bytes)

            self.logger.debug("Request sent (%s)", registers)

            # Wait for response
            res = await asyncio.wait_for(self.notify_future, timeout=5)

            self.logger.debug("Got response")

            return cast(bytes, res)
        except:
            self.logger.warning("Error while reading data")

        return bytes()

    def _calculate_expected_encrypted_length(self, buffer: bytearray) -> int | None:
        """Calculate expected total length of an encrypted message."""
        if len(buffer) < 2:
            return None

        data_len = (buffer[0] << 8) + buffer[1]

        key, iv = self.encryption.getKeyIv()
        if iv is None:
            header_size = 6
        else:
            header_size = 2

        padded_len = (
            (data_len + AES_BLOCK_SIZE - 1) // AES_BLOCK_SIZE
        ) * AES_BLOCK_SIZE

        return header_size + padded_len

    async def _notification_handler(self, _: int, data: bytearray):
        """Handle bt data."""
        self.logger.debug("Got new data (%d bytes)", len(data))

        if self.config.use_encryption is True:
            message = Message(data)

            if message.is_pre_key_exchange:
                message.verify_checksum()

                if message.type == MessageType.CHALLENGE:
                    challenge_response = self.encryption.msg_challenge(message)
                    await self.client.write_gatt_char(WRITE_UUID, challenge_response)
                    return

                if message.type == MessageType.CHALLENGE_ACCEPTED:
                    self.logger.debug("Challenge accepted")
                    return

                return

            if self.encryption.unsecure_aes_key is None:
                self.logger.error(
                    "Received encrypted message before key initialization"
                )
                return

            self.encrypted_buffer.extend(data)

            expected_len = self._calculate_expected_encrypted_length(
                self.encrypted_buffer
            )

            if expected_len is None:
                return

            if len(self.encrypted_buffer) < expected_len:
                self.logger.debug(
                    "Buffering fragment: %d/%d bytes",
                    len(self.encrypted_buffer),
                    expected_len,
                )
                return

            complete_message = bytes(self.encrypted_buffer[:expected_len])

            if len(self.encrypted_buffer) > expected_len:
                self.encrypted_buffer = self.encrypted_buffer[expected_len:]
            else:
                self.encrypted_buffer.clear()

            key, iv = self.encryption.getKeyIv()

            try:
                decrypted = Message(
                    self.encryption.aes_decrypt(complete_message, key, iv)
                )
            except ValueError as e:
                self.logger.error("Decryption failed: %s", e)
                self.encrypted_buffer.clear()
                return

            if decrypted.is_pre_key_exchange:
                decrypted.verify_checksum()

                if decrypted.type == MessageType.PEER_PUBKEY:
                    peer_pubkey_response = self.encryption.msg_peer_pubkey(decrypted)
                    await self.client.write_gatt_char(WRITE_UUID, peer_pubkey_response)
                    return

                if decrypted.type == MessageType.PUBKEY_ACCEPTED:
                    self.encryption.msg_key_accepted(decrypted)
                    return

            # Handle as message
            data = decrypted.buffer

        # Save data
        self.notify_response.extend(data)

        if self.notify_future is None:
            return

        self.notify_future.set_result(self.notify_response)
