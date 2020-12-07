import sys 
import time

FLAG = "REDACTED"
TOTAL_INSERTS = 0

class Node:

	def __init__(self, data):
		self.left = None
		self.right = None
		self.data = data
 
	def insert(self, data):
		newnode = Node(data) 
	 
		x = self  
		y = None
	
		while (x != None):
			y = x 
			if (data < x.data):
				x = x.left 
			else:
				x = x.right 
		 
		if (y == None):
			y = newnode 
	 
		elif (data < y.data):
			y.left = newnode 
		else:
			y.right = newnode 
	 
		return y 

	def findval(self, lkpval, steps=0): 
		if lkpval < self.data:
			if self.left is None: 
				return False 
			return self.left.findval(lkpval, steps+1)
		elif lkpval > self.data:
			if self.right is None: 
				return False 
			return self.right.findval(lkpval, steps+1)
		else:
			return True 

	def PrintTree(self, order=""):
		if self.left:
			self.left.PrintTree("left")
		print( self.data, order),
		if self.right:
			self.right.PrintTree("right")

 
r = Node('')
print((
	"Tell me your pleasure.\n"
	"/a values\n"
	"/s value\n"
	"/p\n"
	"/exit\n"
	)
)

while(True):
	inp = input("Your option: ") 
	if(inp.startswith("/a")):
		values = inp.split(" ")[1].split(";")  
		for val in values:
			if len(values) > 10001:
				break

			TOTAL_INSERTS += 1
			r.insert(val) 

		print(TOTAL_INSERTS)
		sys.stdout.flush()
	elif(inp.startswith("/s")):
		print(r.findval(inp.split(" ")[1])) 
		sys.stdout.flush()
	elif(inp.startswith("/p")):
		print(r.PrintTree())
		sys.stdout.flush()
	elif(inp.startswith("/exit")):
		if(r.findval(FLAG)): 
			sys.stdout.flush()
		break
	else:
		break 

print("Bye!")
sys.exit()