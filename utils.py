import time
import datetime
import random

START_DATETIME = "14/04/2016"
STANDARD_TIME = time.mktime(datetime.datetime.strptime(START_DATETIME, "%d/%m/%Y").timetuple())


def make_id():

    random_time = int(time.time()*1000 - STANDARD_TIME*1000)
    random_bit = random.SystemRandom().getrandbits(23)
    id_number = (random_time << 23) | random_bit
    return id_number


def get_random_time(id_number):
    return id_number >> 23


def get_random_bit(id_number):
    return id_number & 0x7fffff

