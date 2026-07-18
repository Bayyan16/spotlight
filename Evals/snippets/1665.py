# prompt_id=1665
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pill='C:/Users/Gregoire/Documents/CaltechWork/echemdrop/2012-9_FeCoNiTi/results/echemplots/2012-9FeCoNiTi_500C_CAill_plate1_dlist_1164.dat'
    os.chdir('C:/Users/Gregoire/Documents/CaltechWork/echemdrop/2012-9_FeCoNiTi/results/echemplots')
    
    vshift=-.24
    imult=1.e6
    cai0, cai1=(0, 6500)
    
    
    
    f=open(p1, mode='r')
    d1=pickle.load(f)
    f.close()
    
    f=open(p2, mode='r')
    d2=pickle.load(f)
    f.close()
    
    f=open(pill, mode='r')
    dill=pickle.load(f)
    f.close()
