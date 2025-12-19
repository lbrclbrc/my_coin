# node/utils.py

from tools import short_hex

def _truncate_long_hex_in_obj(obj, max_len=80):
    
    if isinstance(obj, dict):
        new_dict = {}
        for k in obj:
            new_dict[k] = _truncate_long_hex_in_obj(obj[k], max_len)
        return new_dict

    if isinstance(obj, list):
        new_list = []
        i = 0
        while i < len(obj):
            new_list.append(_truncate_long_hex_in_obj(obj[i], max_len))
            i += 1
        return new_list

    if isinstance(obj, str):
        s = obj.strip()
        if len(s) > max_len:
            return short_hex(s)
        return s

    return obj
