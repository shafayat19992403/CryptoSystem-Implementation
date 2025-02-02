#!/bin/python3

from typing import Any
from Cryptodome import *
import random
from sympy import isprime
from Crypto.Util import number
# from Crypto.Random import random

class ECurve:
    def __init__(self,a,b,p,nbits):
        self.a = a
        self.b = b
        self.p = p
        self.nbits = nbits

    def check_residue(self,y2):
        temp = (self.p-1)//2
        result = pow(y2, temp, self.p)
        if result == 1 :
            return True
        else:
            return False


    def find_y(self,x):
        first_term = x**2
        second_term = self.a*x
        third_term = self.b

        y2 = first_term + second_term + third_term
        y2 = y2 % self.p

        if self.check_residue(y2):
            exp = (self.p - 1)//4
            result = pow(y2, exp, self.p)
            return result
        else:
            return None

    def describe(self) -> str:
        return f"a: {self.a}, b: {self.b}, p: {self.p}"


def generate_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if isprime(num):
            return num

# We will consider only those
# elliptic curves that have no
# multiple roots - which is
# equivalent to the condition
def generateParameters(bits):
    p = generate_prime(bits)

    temp=[]
    for i in range(2):
        t = random.randint(1, p)
        temp.append(t)

    a = temp[0]
    b = temp[1]

    first_term = (4* a**3) % p

    while True:
        condition_for_single_root = (first_term + 27*b*b)%p == 0

        if condition_for_single_root:
            b = random.randint(1,p)
        else:
            break

    return p,a,b


def generateRandomPointInGraph(curve: ECurve, max_attempts=1000000):
    x = number.getRandomRange(1, curve.p)
    y = curve.find_y(x)

    for _ in range(max_attempts):
        if y:
            return x,y

        x = number.getRandomRange(1, curve.p)
        y = curve.find_y(x)

    return None, None


def generatePrivateKey(curve: ECurve):
    while True:
        private_key = random.getrandbits(curve.nbits)

        Order = int(curve.p + 1 - 2 * curve.p ** 0.5)
        if 1 <= private_key <= Order-1:
            break

    return private_key


def point_addition(x1, y1, x2, y2, curve):
    p = curve.p
    temp_one = number.inverse(x2-x1,p)
    s_without_p = (y2-y1)*temp_one
    s = s_without_p % p
    x3_np = (s*s - x1 - x2)
    x3 = x3_np % p
    y3_np = (s*(x1-x3) - y1)
    y3 = y3_np % p

    return x3,y3


def point_doubling(x1 , y1, curve):
    a = curve.a
    p = curve.p

    temp = number.inverse(2*y1, p)
    s_np = (3 * x1 * x1 + a) * temp
    s = s_np % p
    x3_np = (s*s - x1 - x1)
    x3 = x3_np % p
    y3_np = (s*(x1 - x3) - y1 )
    y3 = y3_np % p

    return x3,y3


def ecc_power_doubleAddAlgo(x, y, exponent, curve):
    num_bits = exponent.bit_length()
    result_x, result_y = x, y
    bit_position = num_bits - 2  # Start from the second-to-last bit

    while True:
        result_x, result_y = point_doubling(result_x, result_y, curve)

        add_current_bit = exponent & 1 << bit_position
        if add_current_bit:
            result_x, result_y = point_addition(result_x, result_y, x, y, curve)

        bit_position -= 1

        if bit_position < 0:
            break

    return result_x, result_y


def createCurve(nbits):
    p,a,b = generateParameters(nbits)
    return ECurve(a,b,p,nbits)


def createGeneratorPoint(generator_point,curve:ECurve):
    if generator_point is None:
        x, y = generateRandomPointInGraph(curve)
    else:
        x = generator_point
        y = curve.find_y(x)
    return x , y


def generateECC_KeyPairs(curve: ECurve,nbits,generator_point):
    if curve is None:
        curve = createCurve(nbits)

    x , y = createGeneratorPoint(generator_point,curve)

    prv_key = generatePrivateKey(curve)
    pub_key = ecc_power_doubleAddAlgo(x,y,prv_key,curve)

    return {
        'curve': curve,
        'public-key-x': pub_key[0],
        'public-key-y': pub_key[1],
        'g-point':x,

    },prv_key


def generateMainKey(ECC_publishable_object,prv_key):
    key, junk = ecc_power_doubleAddAlgo(ECC_publishable_object['public-key-x'],ECC_publishable_object['public-key-y'],prv_key,ECC_publishable_object['curve'])
    return key


# nbits = 128
# object_one, prv1 = generateECC_KeyPairs(None,nbits,None)
# object_two, prv2 = generateECC_KeyPairs(object_one['curve'],nbits,object_one['g-point'])
#
# print(generateMainKey(object_one,prv2))
# print(generateMainKey(object_two,prv1))
#
#
#
#
#
#
#
# curve = ECurve(2,2,17,128)
# print(point_doubling(5,1,curve))
# print(point_addition(5,1,6,3,curve))
# print(ecc_power_doubleAddAlgo(5,1,18, curve))

