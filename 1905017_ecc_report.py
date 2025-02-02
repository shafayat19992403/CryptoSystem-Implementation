import importlib
import time

module_name = '1905017_ecc'
module = importlib.import_module(module_name)



print("k\t\t\t,A\t\t,B,\t\tR")
nbits = [128, 192, 256]

#nbits = 256
for itr_nbit in nbits:
    time_A = 0.0
    time_B = 0.0
    time_R = 0.0

    for i in range(10):
        start_a = time.time()
        object_one, prv1 = module.generateECC_KeyPairs(None, itr_nbit, None)
        end_a = time.time()

        start_b = time.time()
        object_two, prv2 = module.generateECC_KeyPairs(object_one['curve'], itr_nbit, object_one['g-point'])
        end_b = time.time()

        start_r = time.time()
        module.generateMainKey(object_one, prv2)
        end_r = time.time()
        # module.generateMainKey(object_two,prv1)

        time_A += (end_a - start_a)
        time_B += (end_b - start_b)
        time_R += (end_r - start_r)

    time_A = round(time_A * 1000 / 10, 4)
    time_B = round(time_B * 1000/ 10, 4)
    time_R = round(time_R * 1000/ 10, 4)

    print(f"{itr_nbit} bit: ", end='\t')
    print(time_A, end='\t')
    print(time_B, end='\t')
    print(time_R)