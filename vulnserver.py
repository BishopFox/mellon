#!/usr/bin/env python3

"""
To use this library, you'll need the libosdp python bindings. This is unfortunately not in pip for some reason. Blah.
So yea, just follow the build instructions here https://github.com/goToMain/libosdp
NOTE: There is an "osdp" module in pip. This is something different. Don't use that one.
"""

import time
import osdp
import argparse

parser = argparse.ArgumentParser(
                    prog = 'vulnserver.py',
                    description = 'Test OSDP server vulnerable to some attacks')
parser.add_argument('-p', '--port', default="/dev/ttyUSB2")
args = parser.parse_args()

buzzer_cmd = {
    "command": osdp.CMD_BUZZER,
    "reader": 0,
    "control_code": 2,
    "on_count": 2,
    "off_count": 4,
    "rep_count": 1
}

led_cmd = {
    "command": osdp.CMD_LED,
    "reader": 0,
    "led_number": 0,
    "control_code": 2,
    "on_count": 1,
    "off_count": 1,
    "on_color": osdp.LED_COLOR_RED,
    "off_color": osdp.LED_COLOR_GREEN,
    "timer_count": 4,
    "temporary": True
}

# For use when talking over serial directly
pd_info = [
    # PD_0 info
    {
        "address": 4,
        "flags": 0, # osdp.FLAG_ENFORCE_SECURE is 0x00010000
        "scbk": bytes([0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF]),
        "channel_type": "uart",
        "channel_speed": 9600,
        "channel_device": args.port,
    }
]

# For use when talking over local pipe
# pd_info = [
#     # PD_0 info
#     {
#         "address": 4,
#         "flags": 0, # osdp.FLAG_ENFORCE_SECURE
#         "scbk": bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]),
#         "channel_type": "unix_bus",
#         "channel_speed": 9600,
#         "channel_device": '/tmp/osdp_mq',
#     }
# ]

def event_handler(address, event):
    print("Address: ", address, " Event: ", event)
    cp.send_command(0, led_cmd)
    cp.send_command(0, buzzer_cmd)


cp = osdp.ControlPanel(pd_info)

# Print LibOSDP version and source info
print("pyosdp", "Version:", cp.get_version(),
                "Info:", cp.get_source_info())
cp.set_loglevel(osdp.LOG_DEBUG)

cp.set_event_callback(event_handler)

def main():
    global cp
    count = 0  # loop counter
    PD_0 = 0   # PD offset number

    while True:
        cp.refresh()

        # if (count % 100) == 99:
        #     cp.send_command(PD_0, led_cmd)

        count += 1
        time.sleep(0.020) #sleep for 20ms

if __name__ == "__main__":
    main()
