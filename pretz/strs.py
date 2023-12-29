class String:
	def __init__(self, data, is_unicode):
		self.data = data
		self.encoding = 'utf-8'
		if is_unicode:
			self.encoding = 'utf-16'
	def __str__(self):
		return self.data.decode(self.encoding)