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


    ''' Read coils : 0x01
            Request
            RequestFunction code 1 Byte 0x01
            Starting Address 2 Bytes 0x0000 to 0xFFFF
            Quantity of coils 2 Bytes 1 to 2000 (0x7D0) 
    '''

    unit_id = [b"\x00", b"\x01", b"\xFE", b"\xFF"] 
    start_address_values = [b"\x00\x00", b"\x00\x80", b"\xFF\xFF"]  


# ----------------   Read coils ----------------

    quantity_bool_values = [b"\x00\x00", b"\x00\x01", b"\x07\xD0", b"\xFF\xFF"]   # bit_count   
        
    s_initialize(name="modbus_read_coil")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x06", name="length", size=2, fuzzable=False)
    s_group(name="unit_id", values=unit_id)
    s_byte(b"\x01", name="function_code", fuzzable=False)
    s_group(name="start_address", values=start_address_values)
    s_group(name="quantity", values=quantity_bool_values)


    ''' Read descrete inputs 0x02
            Request
            Function code 1 Byte 0x02
            Starting Address 2 Bytes 0x0000 to 0xFFFF
            Quantity of Inputs 2 Bytes 1 to 2000 (0x7D0)
    '''

    s_initialize(name="modbus_read_input")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x06", name="length", size=2, fuzzable=False)
    s_group(name="unit_id", values=unit_id)
    s_byte(b"\x02", name="function_code", fuzzable=False)
    s_group(name="start_address", values=start_address_values)
    s_group(name="quantity", values=quantity_bool_values)

    
# ----------------   Write coils ----------------

    ''' Write single coil
            Request
            Function code 1 Byte 0x05
            Output Address 2 Bytes 0x0000 to 0xFFFF
            Output Value 2 Bytes 0x0000 or 0xFF00
    '''

    data_singe_coil = [b"\x00", b"\x7B", b"\xFF"]    

    s_initialize(name="modbus_write_coil")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x06", name="length", size=2, fuzzable=False)
    s_group(name="unit_id", values=unit_id)
    s_byte(b"\x05", name="function_code", fuzzable=False)
    s_group(name="start_address", values=start_address_values)
    s_group(name="data", values=data_singe_coil)
    s_bytes(b"\x00", name="padding", size=1, fuzzable=False)


   

    ''' Write multiple coils: 0x0f  (15)
            Request PDU
            Function code 1 Byte 0x0F
            Starting Address 2 Bytes 0x0000 to 0xFFFF
            Quantity of Outputs 2 Bytes 0x0001 to 0x07B0
            Byte Count 1 Byte N*
            Outputs Value N* x 1 Byte
    '''
    
    quantity_write_values = [b"\x00\x00", b"\x00\x01", b"\x07\xB0", b"\xFF\xFF"]
    byte_count_values = [b"\x00", b"\x01", b"\xf6",  b"\xff"]    # max 246 byte =  1968(0x07b0)bit
    data_multiple_coil = [b"\x00\x00", b"\x7F\xFF", b"\xFF\xFF"]    


    s_initialize(name="modbus_write_multiple_coils")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x08", name="length", size=2, fuzzable=False)  
    s_bytes(b"\x01", name="unit_id", size=1, fuzzable=False)
    s_byte(b"\x0f", name="function_code", fuzzable=False)
    s_group(name="start_address", values=start_address_values)
    s_group(name="quantity", values=quantity_write_values)
    s_group(name="byte_count", values=byte_count_values)
    s_group(name="coil_value", values=data_multiple_coil)


# ----------------   Read registers ----------------



    '''Read holding resgisters:0x03
            Request
            Function code 1 Byte 0x03
            Starting Address 2 Bytes 0x0000 to 0xFFFF
            Quantity of Registers 2 Bytes 1 to 125 (0x7D)
    '''
    quantity_word_values = [b"\x00\x00", b"\x00\x01", b"\x00\x7D", b"\xFF\xFF"]    


    s_initialize(name="modbus_read_holding_registers")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x06", name="length", size=2, fuzzable=False)
    s_group(name="unit_id", values=unit_id)
    s_byte(b"\x03", name="function_code", fuzzable=False)
    s_group(name="start_address", values=start_address_values)
    s_group(name="quantity", values=quantity_word_values)



    '''Read input resgisters:0x04
            Request
            Function code 1 Byte 0x04
            Starting Address 2 Bytes 0x0000 to 0xFFFF
            Quantity of Input Registers 2 Bytes 0x0001 to 0x007D
    '''

    s_initialize(name="modbus_read_input_registers")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x06", name="length", size=2, fuzzable=False)
    s_group(name="unit_id", values=unit_id)
    s_byte(b"\x04", name="function_code", fuzzable=False)
    s_group(name="start_address", values=start_address_values)
    s_group(name="quantity", values=quantity_word_values)



# ----------------   Write registers ----------------


    '''Write Single Register:0x06
            Request
            Function code 1 Byte 0x06
            Register Address 2 Bytes 0x0000 to 0xFFFF
            Register Value 2 Bytes 0x0000 to 0xFFFF
    '''

    s_initialize(name="modbus_write_holding_registers")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x06", name="length", size=2, fuzzable=False)
    s_group(name="unit_id", values=unit_id)
    s_byte(b"\x06", name="function_code", fuzzable=False)
    s_group(name="start_address", values=start_address_values)
    s_group(name="quantity", values=quantity_word_values)




    '''Write multiple holding: 0x10  (16)
            Request
            Function code 1 Byte 0x10
            Starting Address 2 Bytes 0x0000 to 0xFFFF
            Quantity of Registers 2 Bytes 0x0001 to 0x007B
            Byte Count 1 Byte 2 x N*
            Registers Value N* x 2 Bytes value
    '''

    quantity_write_holding_values = [b"\x00\x00", b"\x00\x01", b"\x00\x7B", b"\xFF\xFF"]
    byte_count_holding_values = [b"\x00", b"\x01", b"\xf6",  b"\xff"]    # 2 x Quantity = max  123 * 2 = 246
    value_holding =  [b"\x00\x00", b"\x7F\xFF", b"\xFF\xFF"] 

    s_initialize(name="modbus_write_multiple_holding")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x08", name="length", size=2, fuzzable=False)  
    s_bytes(b"\x01", name="unit_id", size=1, fuzzable=False)
    s_byte(b"\x10", name="function_code", fuzzable=False)
    s_group(name="start_address", values=start_address_values)
    s_group(name="quantity", values=quantity_write_holding_values)
    s_group(name="byte_count", values=byte_count_holding_values)
    s_group(name="value", values=value_holding)



    session.connect(s_get("modbus_read_coil"))
    session.connect(s_get("modbus_read_input"))
    session.connect(s_get("modbus_write_coil"))
    session.connect(s_get("modbus_write_multiple_coils"))
    session.connect(s_get("modbus_read_holding_registers"))
    session.connect(s_get("modbus_read_input_registers"))
    session.connect(s_get("modbus_write_holding_registers"))
    session.connect(s_get("modbus_write_multiple_holding"))

    session.fuzz()

if __name__ == "__main__":
    main()