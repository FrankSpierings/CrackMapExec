from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import FILE_READ_DATA
import re

import logging
log = logging.getLogger()
logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s',
                    level=logging.DEBUG, datefmt='%I:%M:%S')
log.setLevel(logging.INFO)


class Spider():
	class Match():
		def __init__(self, path, pattern, isfile=False):
			self.path = path
			self.pattern = pattern
			self.isfile = isfile

		def __str__(self):
			return "'{}'\t'{}'\t{}".format(self.path, self.pattern, self.isfile)


	def __init__(self, conn, share, path, extensions=None, path_re=None, content_re=None, path_re_ex=None):
		# 32MB Blocksize
		self.BLOCKSIZE = 32000000

		self.conn = conn

		if extensions and not isinstance(extensions, list):
			extensions = [extensions]
		self.extensions = extensions

		if path_re and not isinstance(path_re, list):
			path_re = [path_re]
		self.path_re = path_re
		
		if content_re and not isinstance(content_re, list):
			content_re = [content_re]
		self.content_re = content_re

		if path_re_ex and not isinstance(path_re_ex, list):
			path_re_ex = [path_re_ex]
		self.path_re_ex = path_re_ex

		if path == '.' or path == '/' or path == './':
			path = ''
		self.path = path

		self.matches = []

	def __fullpath(self, path):
		return '//{}{}'.format(self.conn.getRemoteHost(), path)

	def __smbpath(self, path):
		if path == '':
			return '*/'
		else:
			return '{}/*'.format(path)

	def spider(self):
		self.__spider(path=self.path)

	def __spider(self, path):
		logging.debug('Directory: {}'.format(self.__fullpath(path)))
		
		try:
			entries = self.conn.listPath(self.share, self.__smbpath(path))
		except SessionError as e:
			if not 'STATUS_ACCESS_DENIED' in str(e):
				log.warning('Path "{}", error: {}'.format(self.__fullpath(path), str(e)))
			return

		for entry in entries:
			name =  entry.get_longname()
			entrypath = '{}/{}'.format(path, name)
			if name == '.' or name == '..':
				continue
			
			# Directory
			if entry.is_directory():
				if not self.__match_path_ex('{}/'.format(entrypath)):
					self.__match_path(entrypath)
					self.__spider(entrypath)
			# File
			else:
				if not self.__match_path_ex('{}'.format(entrypath)):
					self.__match_path(entrypath, True)
					self.__match_content(entrypath)
					logging.debug('File: {}'.format(self.__fullpath(entrypath)))

	def __match_path_ex(self, path):
		if self.path_re_ex is not None:
			for pattern in self.path_re_ex:
				if re.search(pattern, path):
					log.debug("Exlusion matched: '{}'\tPattern: '{}'".format(self.__fullpath(path), pattern))
					return True
		return False

	def __match_path(self, path, isFile=False):
		if self.path_re:
			for pattern in self.path_re:
				if re.findall(pattern, path):
					log.info("Path matched: '{}'\tPattern: '{}'".format(self.__fullpath(path), pattern))
					match = self.Match(self.__fullpath(path), pattern, )

	def __match_content(self, path):
		if self.extensions:
			found = False
			for extension in self.extensions:
				if path.endswith(extension):
					log.debug("Extension matched: '{}'\tPattern: '{}'".format(self.__fullpath(path), extension))
					break
			if not found:
				return

		tid = self.conn.connectTree(self.share)
		
		try: 
			fid = self.conn.openFile(tid, path, desiredAccess=FILE_READ_DATA)
			cur = 0
			data = self.conn.readFile(tid, fid, cur, self.BLOCKSIZE)
			while data is not None and data is not '':
				cur = cur + len(data)
				for pattern in self.content_re:
					if re.findall(pattern, data, re.IGNORECASE):
						log.info("Content matched: '{}'\tPattern: '{}'".format(self.__fullpath(path), pattern))
						return
				data = self.conn.readFile(tid, fid, cur, self.BLOCKSIZE)
			self.conn.closeFile(tid, fid)
		except:
			log.debug('Could not open: {0}'.format(self.__fullpath(path)))



address = '10.0.0.1'
target_ip = address
port = 445

con = SMBConnection(address, target_ip, sess_port=int(port))
con.login(user='user01', password='Password123!', domain='lab.test')
# spider('test$','.')

spider = Spider(con, share='Windows', path='.', path_re=['password'], content_re=['password', 'wacHtwoord'], extensions=['.txt', '.xml'])
spider.spider()