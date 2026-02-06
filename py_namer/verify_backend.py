from device_mgr import DeviceManager
import sys

def test_backend():
    print("Initializing DeviceManager...")
    mgr = DeviceManager()
    
    print("Listing potential devices...")
    devices = mgr.list_potential_devices()
    print(f"Found {len(devices)} potential devices: {devices}")
    
    for dev in devices:
        print(f"--- Info for {dev} ---")
        info = mgr.get_device_info(dev)
        print(info)
        
        print("Generating rule preview...")
        rule = mgr.generate_rule_content(info, "test_symlink_name")
        print(rule)
        print("----------------------")
        
    print("Backend verification complete.")

if __name__ == "__main__":
    test_backend()
