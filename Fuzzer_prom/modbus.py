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
        sleep_time=0.1,
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



# ---------------- function codes --------------
       
    s_initialize(name="modbus_function_codes")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x06", name="length", size=2, fuzzable=False)
    s_group(name="unit_id", values=unit_id)
    s_byte(b"\x00", name="function_code", fuzzable = True, full_range=True)
    s_bytes(b"\x00\x00\x00\x00", fuzzable=False)



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
    s_group(name="unit_id", values=unit_id)
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
    s_group(name="unit_id", values=unit_id)
    s_byte(b"\x10", name="function_code", fuzzable=False)
    s_group(name="start_address", values=start_address_values)
    s_group(name="quantity", values=quantity_write_holding_values)
    s_group(name="byte_count", values=byte_count_holding_values)
    s_group(name="value", values=value_holding)




   #  ----------------   Only serial Line  but ...  ----------------
    ''' 07 (0x07) Read Exception Status (Serial Line only)  - 
                Request Function code 1 Byte 0x07  - отпавляется в функции  modbus_function_codes '''


    ''' 08 (0x08) Diagnostics (Serial Line only) 
                Request 
                Function code 1 Byte 0x08 
                Sub-function 2 Bytes 
                Data N x 2 Bytes  

    '''
    diagnostic_data = [b"\x00\x00", b"\x00\x01", b"\x00\x02", b"\x00\x03", b"\x00\x04", b"\x00\x05", b"\x00\x06", b"\x00\x07", \
                       b"\x00\x08", b"\x00\x09", b"\x00\x0A", b"\x00\x0B", b"\x00\x0C", b"\x00\x0D", b"\x00\x0E", b"\x00\x0F", \
                       b"\x00\x10", b"\x00\x11", b"\x00\x12", b"\x00\x13", b"\x00\x14", b"\x00\x15", b"\xFF\xDC", b"\xFF\xFF"] 
    

    diagnostic_value = [b"\x00\x00", b"\x00\xFF", b"\xFF\x00", b"\xFF\xFF", b"\x00\x04"]
    s_initialize(name="Diagnostics")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x06", name="length", size=2, fuzzable=False)  
    s_group(name="unit_id", values=unit_id)
    s_byte(b"\x08", name="function_code", fuzzable=False)
    s_group(name="code", values = diagnostic_data )
    s_group(name="data", values= diagnostic_value)


    ''' 11 (0x0B) Get Comm Event Counter (Serial Line only) 
            Request 
            Function code 1 Byte 0x0B '''

    s_initialize(name="Get_Comm_Event_Counter")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x06", name="length", size=2, fuzzable=False)  
    s_group(name="unit_id", values=unit_id)
    s_byte(b"\x0B", name="function_code", fuzzable=False)


    ''' 12 (0x0C) Get Comm Event Log  (Serial Line only)
            Request 
            Function code 1 Byte 0x0C
    '''
    s_initialize(name="Get_Comm_Event_Log")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x06", name="length", size=2, fuzzable=False)  
    s_group(name="unit_id", values=unit_id)
    s_byte(b"\x0C", name="function_code", fuzzable=False)


    '''17 (0x11) Report Slave ID (Serial Line only) 
            Request 
            Function code 1 Byte 0x11
    '''

    s_initialize(name="Report_Slave_ID")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x06", name="length", size=2, fuzzable=False)  
    s_group(name="unit_id", values=unit_id)
    s_byte(b"\x11", name="function_code", fuzzable=False)

    ''' 20 (0x14) Read File Record
            Function code 1 Byte 0x14 
            Byte Count 1 Byte 0x07 to 0xF5 bytes 
            Sub-Req. x, Reference Type 1 Byte 06 
            Sub-Req. x, File Number 2 Bytes 0x0001 to 0xFFFF 
            Sub-Req. x, Record Number 2 Bytes 0x0000 to 0x270F 
            Sub-Req. x, Record Length 2 Bytes N 
            Sub-Req. x+1, ..
    '''
    byte_count_20 = [b"\x00", b"\x07", b"\xF5", b"\xFF"]
    reference_type = [b"\x00", b"\x06", b"\xFF"]
    file_number = [b"\x00\x01", b"\x7F\xFF", b"\xFF\xFF"]
    record_number = [b"\x00\x00", b"\x27\x0F", b"\xFF\xFF"]
    record_length = [b"\x00\x01", b"\x7F\xFF", b"\xFF\xFF"]

    s_initialize(name="Read_File_Record")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x0A", name="length", size=2, fuzzable=False)  
    s_group(name="unit_id", values=unit_id)
    s_byte(b"\x14", name="function_code", fuzzable=False)
    s_group(name="ByteCount", values=byte_count_20)
    s_group(name="ReferenceType", values=reference_type)
    s_group(name="file_number", values=file_number)
    s_group(name="record_number", values=record_number)
    s_group(name="record_length", values=record_length)


    ''' 21 (0x15) Write File Record
        Request  
        Function code 1 Byte 0x15 
        Request data length 1 Byte 0x09 to 0xFB 
        Sub-Req. x, Reference Type 1 Byte 06 
        Sub-Req. x, File Number 2 Bytes 0x0001 to 0xFFFF 
        Sub-Req. x, Record Number 2 Bytes 0x0000 to 0x270F 
        Sub-Req. x, Record length 2 Bytes N 
        Sub-Req. x, Record data N x 2 Bytes  
        Sub-Req. x+1, ...
'''

    request_data_length = [b"\x00", b"\x09", b"\xFB", b"\xFF"]
    record_data = [
        b"\x00\x01\x00\x02\x00\x03\x00\x04",  
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 
        b"\x00\x00\x00\x00\x00\x00\x00\x00",  
        b"\xDE\xAD\xBE\xEF\x12\x34\x56\x78"
    ]
    s_initialize(name="Write_File_Record")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x0C", name="length", size=2, fuzzable=False)  
    s_group(name="unit_id", values=unit_id)
    s_byte(b"\x15", name="function_code", fuzzable=False)
    s_group(name="RequestDataLength", values=request_data_length)
    s_group(name="ReferenceType", values=reference_type)
    s_group(name="file_number", values=file_number)
    s_group(name="record_number", values=record_number)
    s_group(name="record_length", values=record_length)
    s_group(name="record_data", values=record_data)



    '''22 (0x16) Mask Write Register
        Request  
            Function code 1 Byte 0x16 
            Reference Address 2 Bytes 0x0000 to 0xFFFF 
            And_Mask 2 Bytes 0x0000 to 0xFFFF 
            Or_Mask 2 Bytes 0x0000 to 0xFFFF
    '''
    reference_adress = [b"\x00\x00", b"\x00\x01", b"\x7F\xFF", b"\xFF\xFF"]
    and_mask  = [b"\x00\x00", b"\x00\x01",  b"\x7F\xFF", b"\xFF\xFF"]
    or_mask  = [b"\x00\x00",  b"\x00\x01", b"\x7F\xFF", b"\xFF\xFF"]

    s_initialize(name="Mask_Write_Register")
    s_bytes(b"\x00\x01", name="transaction_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x00", name="protocol_id", size=2, fuzzable=False)
    s_bytes(b"\x00\x08", name="length", size=2, fuzzable=False)  
    s_group(name="unit_id", values=unit_id)
    s_byte(b"\x16", name="function_code", fuzzable=False)
    s_group(name="reference_adress", values=reference_adress)
    s_group(name="and_mask", values=and_mask)
    s_group(name="or_mask", values=or_mask)


    session.connect(s_get("modbus_function_codes"))
    session.connect(s_get("modbus_read_coil"))
    session.connect(s_get("modbus_read_input"))
    session.connect(s_get("modbus_write_coil"))
    session.connect(s_get("modbus_write_multiple_coils"))
    session.connect(s_get("modbus_read_holding_registers"))
    session.connect(s_get("modbus_read_input_registers"))
    session.connect(s_get("modbus_write_holding_registers"))
    session.connect(s_get("modbus_write_multiple_holding"))

    # serial only
    # session.connect(s_get("Diagnostics"))
    # session.connect(s_get("Get_Comm_Event_Counter"))
    # session.connect(s_get("Get_Comm_Event_Log"))
    # session.connect(s_get("Report_Slave_ID"))
    # # session.connect(s_get("Read_File_Record"))
    # # session.connect(s_get("Write_File_Record"))
    # session.connect(s_get("Mask_Write_Register"))

    session.fuzz()

if __name__ == "__main__":
    main()