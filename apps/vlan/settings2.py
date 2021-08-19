import pickle
import logging

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)



def save(nat_dict,filename):
    try:
        with open(filename, 'wb') as fp:
            pickle.dump(nat_dict, fp)
        return True
    except:
        logging.warning('Failed when saving pickled')
        return False


def load(filename):
    try:
        with open(filename, 'rb') as fp:
            return pickle.load(fp)
    except:
        logging.warning('Failed when loading pickled')
        return None
