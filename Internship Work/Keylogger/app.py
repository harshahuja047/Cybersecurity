# importing different modules from the pynput library  
from pynput.keyboard import Controller  
  
# instantiating the Controller class  
the_keyboard = Controller()  
  
# using the press() and release() methods  
the_keyboard.press('x')  
the_keyboard.release('x')  
the_keyboard.press('y')  
the_keyboard.release('y')  
the_keyboard.press('z')  
the_keyboard.release('z')  