import angr
import claripy

# Initialize the angr project with the binary
p = angr.Project('./rage1', auto_load_libs=False)

# Create symbolic variables for the input
argv1 = claripy.BVS("argv1", 8 * 8)  # 8 characters for the first string
argv2 = claripy.BVS("argv2", 8 * 8)  # 8 characters for the second string
argv3 = claripy.BVS("argv3", 8 * 8)  # 8 characters for the third string
argv4 = claripy.BVS("argv4", 8 * 8)  # 8 characters for the fourth string

# Concatenate the symbolic variables to form the full input
input_data = argv1 + argv2 + argv3 + argv4

# Create an initial state with the symbolic input as stdin
init_state = p.factory.full_init_state(
    args=['./rage1'],
    stdin=input_data
)

# Create a simulation manager with the initial state
simgr = p.factory.simgr(init_state)

# Define the target address where the 'puts Good' instruction is located
target = 0x08049869

# Explore paths to find a state that reaches the target address
simgr.explore(find=target)

# Check if a solution state that reaches the target address was found
if simgr.found:
    solution_state = simgr.found[0]
    # Print the input that leads to the solution state
    found_input = solution_state.posix.dumps(0)
    
    # Split the input into the four separate buffers
    buffer0 = found_input[:8]
    buffer1 = found_input[8:16]
    buffer2 = found_input[16:24]
    buffer3 = found_input[24:32]

    print("Buffer0:", buffer0)
    print("Buffer1:", buffer1)
    print("Buffer2:", buffer2)
    print("Buffer3:", buffer3)
