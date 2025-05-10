from boofuzz import *
import socket


host = "192.168.1.5"
port = 502


class CrashOnlyLogger(FuzzLogger):
    def log_fail(self, description=""):
        # Логируем только сбои, связанные с падением
        print(f"CRASH DETECTED: {description}")

    # Переопределяем остальные методы, чтобы они ничего не выводили
    def log_info(self, description=""):
        pass

    def log_error(self, description=""):
        print(f"ERROR DETECTED: {description}")

    def log_check(self, description=""):
        pass

    def log_recv(self, data=""):
        pass

    def log_send(self, data=""):
        pass

def main():
    session = Session(
        target=Target(
            connection=SocketConnection(host, port, proto="tcp")
        ),
        web_port=26000,
        fuzz_loggers=[CrashOnlyLogger()],
        reuse_target_connection=True,
        #sleep_time=0.03,
        receive_data_after_fuzz=True,
        check_data_received_each_request=True,
    )



    # Read coils : 0x01
    s_initialize(name="modbus_read_coil")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x06", name="length", size=2, fuzzable=False)
    s_bytes(b"\x01", name="unit_id", size=1, fuzzable=False)
    s_byte(b"\x01", name="function_code", fuzzable=False)
    s_bytes(b"\x00\x00", name="start_address", size=2, fuzzable=True)
    s_bytes(b"\x00\x01", name="quantity", size=2, fuzzable=True)


    # Write single coil
    s_initialize(name="modbus_write_coil")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x06", name="length", size=2, fuzzable=False)
    s_bytes(b"\x01", name="unit_id", size=1, fuzzable=False)
    s_byte(b"\x05", name="function_code", fuzzable=False)
    s_bytes(b"\x00\x00", name="start_address", size=2, fuzzable=True)
    s_byte(b"\x00", name="data", fuzzable=True)
    s_bytes(b"\x00", name="padding", size=1, fuzzable=False)


    # Read descrete inputs 0x02
    s_initialize(name="modbus_read_input")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x06", name="length", size=2, fuzzable=False)
    s_bytes(b"\x01", name="unit_id", size=1, fuzzable=False)
    s_byte(b"\x02", name="function_code", fuzzable=False)
    s_bytes(b"\x00\x00", name="start_address", size=2, fuzzable=True)
    s_bytes(b"\x00\x01", name="quantity", size=2, fuzzable=True)

    # Write multiple coils: 0x0f  (15)
    start_address_values = [b"\x00\x00", b"\x00\x80", b"\xFF\xFF"]  
    quantity_values = [b"\x00\x01", b"\x00\x80", b"\xFF\xFF"]   # bit_count    
    byte_count_values = [b"\x01", b"\x7e",  b"\xff"]  

    s_initialize(name="modbus_write_multiple_coils")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x08", name="length", size=2, fuzzable=False)  
    s_bytes(b"\x01", name="unit_id", size=1, fuzzable=False)
    s_byte(b"\x0f", name="function_code", fuzzable=False)
    s_group(name="start_address", values=start_address_values)
    s_group(name="quantity", values=quantity_values)
    s_group(name="byte_count", values=byte_count_values)
    s_byte(b"\x00", name="coil_values", fuzzable=True)


    session.connect(s_get("modbus_read_coil"))
    session.connect(s_get("modbus_write_coil"))
    session.connect(s_get("modbus_read_input"))
    session.connect(s_get("modbus_write_multiple_coils"))
    session.fuzz()

if __name__ == "__main__":
    main()