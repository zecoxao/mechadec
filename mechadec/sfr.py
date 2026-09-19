"""
MechaCon RAM and I/O symbol names.

The SPC970 core itself has no fixed peripheral map -- these names belong to the
PlayStation 2 MechaCon platform and come from the established MechaCon
reverse-engineering work carried in DiscoStarslayer's ``ghidra-spc970``
(``MechaConSymbols.java``).  They are applied only when a program is recognised
as MechaCon firmware, so a bare SPC970 image is never mislabelled.

``RAM_NAMES`` is keyed by a 24-bit data address, ``IO_NAMES`` by the 8-bit port
number used by the table-1 BSET/BCLR/BBC/BBS short forms.
"""

RAM_NAMES = {
    # core status / error plumbing
    0x000018: "Mech_Error_Flags",
    0x000036: "DSP_Spindle_Speed_Mode",
    0x000054: "Disc_Max_LBA",
    0x0000A5: "HW_REG_TIME_MIN",
    0x0000A6: "HW_REG_TIME_SEC",
    0x0000A7: "HW_REG_TIME_FRAME",
    0x000100: "HW_Drive_Current_Status",
    0x000101: "HW_PORT_Syscon_Signal",
    0x000102: "HW_PORT_Sensor_Switches",
    0x000107: "HW_TestPin_Reg_bit4",
    0x0002B2: "HW_TIMER_CONTROL",
    0x000300: "HW_SIO_TX_BUFFER",
    0x000301: "HW_SIO_RX_BUFFER",
    0x000520: "Drive_Active_State",
    0x000608: "HW_SLED_MOTOR_STATUS",

    # authentication / MagicGate state
    0x0009B6: "CDVD_Mode",
    0x0009B7: "auth_b7",
    0x0009B8: "auth_b8",
    0x0009B9: "Mecha_ErrorCode",
    0x0009BA: "MG_CardKeySlot",
    0x0009BC: "MG_CardKeyIndex",
    0x0009BE: "MG_Key_Status_Array",
    0x0009CE: "Mecha_State",
    0x0009D0: "Mecha_Result",
    0x0009D2: "MG_LastBitTable",
    0x0009D4: "MG_Data_Size",
    0x0009D6: "MG_Buffer_Offset",
    0x0009D8: "MG_Data_Out_Offset",
    0x0009DE: "MG_CurrentBlockIdx",
    0x0009E2: "MG_Data_Buffer",
    0x001572: "MG_Memcard_Nonce",
    0x0015CA: "MG_Pub_Kc_Part2",

    # SCMD / NCMD protocol buffers
    0x001744: "NCMD_Rx_Cmd_ID",
    0x001745: "NCMD_Rx_ParamCnt",
    0x001746: "NCMD_Rx_ParamBuff",
    0x001756: "scmd_in_cmd",
    0x001757: "scmd_in_len",
    0x001758: "scmd_in_params",
    0x001768: "NCMD_Current_Cmd_ID",
    0x00176A: "NCMD_Args",
    0x00177A: "NCMD_Status_Flag",
    0x00177C: "SCMD_Input_Args",
    0x00177D: "scmd_len",
    0x00177E: "scmd_params",
    0x0017B6: "RAM_PMAP_Arg_Buffer",
    0x0017CC: "NCMD_Target_LBA",
    0x0017D4: "NCMD_Sector_Count",
    0x0017EC: "Mecha_Hardware_Ready_Flags",
    0x0017EE: "RAM_PS2ID_Buffer",
    0x0017FE: "RAM_EEPROM_Verify_PS2ID",

    # configuration blocks
    0x00180E: "RAM_ModelName_Config",
    0x001820: "RAM_DiscDetect_Config",
    0x001834: "RAM_Servo_Config",
    0x001898: "RAM_Tilt_Config",
    0x0018A4: "RAM_EEGS_Config",
    0x0018E4: "RAM_OSD_Config",
    0x001954: "RAM_DVDPlayer_Config",
    0x0019C7: "Drive_State",
    0x001A10: "RAM_EEPROM_Task_Flags",
    0x001A24: "RAM_EEPROM_Target_Addr",
    0x001A38: "RAM_Tray_Config",
    0x001A68: "Servo_Mechanics_Enable",
    0x001AD6: "RAM_Detect_State_Machine",
    0x001AF6: "RAM_Calibration_Status",

    # RTOS / crypto engine
    0x001B08: "RTOS_Msg_Param",
    0x001B0A: "Crypto_Msg_Command",
    0x001B72: "MG_Keys_Buffer",
    0x001B92: "MG_Data_IV_Buffer",
    0x001BAB: "Crypto_Engine_State",
    0x001D04: "RAM_Disc_Type",

    # DSP / servo
    0x00200E: "DSP_Tracking_Limit",
    0x002012: "DSP_Focus_Upper_Limit",
    0x002014: "DSP_Focus_Lower_Limit",
    0x002029: "DSP_Multiplier",
    0x0020A8: "DSP_Focus_Gain",

    # UART diagnostics
    0x0020D8: "UART_Flag_Enable",
    0x0020DC: "RX_Buffer",
    0x0020EE: "TX_Packet_Length",
    0x0020EF: "TX_Error_Flag",
    0x0020F0: "TX_Payload",
}

IO_NAMES = {
    0x18: "IO_Mech_Error_Flags",
    0x36: "IO_Spindle_Mode",
    0xA5: "IO_TIME_MIN",
    0xA6: "IO_TIME_SEC",
    0xA7: "IO_TIME_FRAME",
}


def ram_name(addr):
    return RAM_NAMES.get(addr & 0xFFFFFF)


def io_name(port):
    return IO_NAMES.get(port & 0xFF)
