from unicorn import *
from unicorn.x86_const import *
import base64

b64_string = "f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAqAAAAAAAAAA6AAAAAAAAAAAAAAAAAAAAAAAAADoAOAACAAEAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiAMAAAAAAACIAwAAAAAAAAAQAAAAAAAAAgAAAAEAAAAFAAAAAAAAAHoAAAAAAAAADAAAAAAAAACoAAAAAAAAAAYAAAAAAAAAAAAAAAAASIPk8Os/XugwAAAAVF6A8l9VXzRPDwWwIkGSsAkx/74AIAAAsgcPBetwXlBfVVm1AfNIpf/QMcCwPA8FsAFQX7JPDwXD6Lz///9IaSEgVGhpcyBpcyBhIHJldmVyc2UgZW5naW5lZXJpbmcgY2hhbGxlbmdlLgpXaGF0IGlzIHlvdXIgaW5wdXQ/ClBsZWFzZSBlbnRlciA6AOiL////WF5fSLvZRG9XBj6eZrExMdLa1UgPrgQkXV1IMVzVF0gDXNUX/8Li8pH/yoj97Zr3smakGzPAeSL8aWhnF7kghc0poX8fQofAOi2LYm2pU5qCE5eOj85ga8Rv4ZuHmJYCzVfCqheT5BnvD+vYMjxmJCBV5+mGt5M0vu6qS21vwhJWHrQuuAMFwv9nUlQUv5+pdr41aE0YppWvRa0JdfFqGfsymiP6LGI3J9YehfrJ2vNHUrGeiP5qcRaGsMjyW1ebE4p3w3t0h1/q9QeAwgRy4vQSvIghiSMq5CngvukngVjX94dFHPV5Wzg2zyh9OW65bGoZS8zh8RahHrIJYbdj24bcDoZ+WnYuasJJKGMi+ZOx+3HM+aklF4BrXc4hq/AF47yIvFeqKDzFE+IqsLcrW4L5L1ASHwfYrHJVACXJe9YTyZmorGZolaovulL8Xl8CAmNj7VkrpL6zwCsT2ZERiblU90LgDSrsdCi3zLUUxCIWZelRPGVgRocsl1jMpkyALgeR6l+MsNMGixhTPXzUE9J/8jfq8bF7yjB4FhMIeLW8cSrvg0inRebheOYoj1i6/XugwAAAAVF6A8l9VXzRPDwWwIkGSsAkx/74AIAAAsgcPBetwXlBfVVm1AfNIpf/QMcCwPA8FsAFQX7JPDwXD6Lz///9IaSEgVGhpcyBpcyBhIHJldmVyc2UgZW5naW5lZXJpbmcgY2hhbGxlbmdlLgpXaGF0IGlzIHlvdXIgaW5wdXQ/ClBsZWFzZSBlbnRlciA6AOiL////WF5fSLsibSzc8zpV+bE2MdLa1UgPrgQkXV1IMVzVF0gDXNUX/8Li8mrWbfQ1TAMhoDDfNYtjcQR8TrEyz97b700MGC1H4r86ulNgsKXtrAAUQPeppKft8qSyCSriOd3Wid1Ba7+aciRIP8NxOA+g6O18/dHnkxAg69z58mjbdtoYqRft52sWk03NbT2gjTwJMv8JvdiJJJMzYruokdO8DYUTLOIMq8QUK7e2Ddk03Si5F3NobBjQaqdmLwKKQA9xoGIzZ5gjEQu1zoi2RjFhb1B5f4kdEL52EwNmNNIbFEwyqWY+ucvRCFiAbzZMyhf+iZTUBAU+dzBjEJwGLyHP74kBltNBb/e5rh0doMnhm76EU5F21RlcvaQO2gXpDm7tJM/IGXrKZko5RNk5s+NSkf6/iZy8XznODZFKSlWBDB4Z/kA/Mz+7yJqTXS5ROZc+3GOwmfMSqr58uYKMXtJugzH+MQYkV1cYq8bxZJV0QFMetnsWc7uxNFNjQk/QkXgc1i9ZNZS+S5MnxbIjz0D9xZUUjw3ucdobaDNzDvhsLJDnjGxMQdQR/dUJjobM5k0KB/26rpClWuHxc+Yusda5nnm6cpdABKJKgA/rSF3l0h2H3pq5ogodIg=="
binary_data = base64.b64decode(b64_string)
# Machine code to emulate: INC ecx; DEC edx
X86_CODE = binary_data
STACK_ADDR = 0x2000000
STACK_SIZE = 0x2000
# Base address for memory mapping
ADDRESS = 0x0000000

def hook_code(uc, address, size, user_data):
    """
    Callback function for code execution hooks.
    Prints the address and the instruction being executed.
    """
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))

def hook_mem_invalid(uc_handle, access, address, size, value, user_data):
    page = address & ~(0x1000 - 1)
    try:
        uc_handle.mem_map(page, 0x1000, UC_PROT_ALL)
        uc_handle.mem_write(page, b"\x00" * 0x1000)
        print(f"[+] Lazily mapped page 0x{page:x}")
        return True
    except UcError as e:
        print("[!] lazy map failed:", e)
        return False

def main():
    try:
        # Initialize Unicorn in x86 32-bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # Map 2MB of memory for emulation
        mu.mem_map(ADDRESS, 8 * 1024 * 1024)
        mu.mem_map(STACK_ADDR, STACK_SIZE)
        # Write the x86 code to the mapped memory
        mu.mem_write(ADDRESS, X86_CODE)

        # Set initial register values
        # Add a hook to trace code execution
        mu.hook_add(UC_HOOK_CODE, hook_code)
        
        mu.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
            hook_mem_invalid
        )
        # Emulate the code
        print("Emulating x86 code...")
        mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE))

        # Read the final register values
        ecx_val = mu.reg_read(UC_X86_REG_ECX)
        edx_val = mu.reg_read(UC_X86_REG_EDX)

        print(f"ECX after emulation: 0x{ecx_val:x}")
        print(f"EDX after emulation: 0x{edx_val:x}")

    except UcError as e:
        print("ERROR: %s" % e)

if __name__ == "__main__":
    main()