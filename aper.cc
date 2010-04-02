/*
Copyright (C) 2010 University of Minnesota.  All rights reserved.
$Id: aper.cc,v 1.3 2010/04/02 21:24:10 shollatz Exp $

	aper.cc - add bulk APER formated addresses to text databases
	20090619.1532 s.a.hollatz <shollatz@d.umn.edu>

NOTES

[a] Use:  aper list [file]
	where 'list' is one of the following:

		reply	-- add to phish reply list
		cleared	-- add to phish cleared list used by reply
		links	-- add to phish links list
		help	-- simple command usage

	Reads from stdin if file isn't given.
	The file format follows the "standard" APER form, one entry per line.

[b] Inspired by 'add-address-to-list.pl' by Jesse Thompson.

[c] Compile: c++ -s -o aper aper.cc

	This compiles "aper.cc" to the executable "aper".
	Of course, you can name the executable whatever you like.

	Builds OK with GNU C++ compiler on Solaris and Debian platforms.
	Not tested build with other compilers or platforms.

	Ideally, this should be complied into separate modules then linked.

[d] Kludgeware reigned over cleverness.  The next version will be a refactor.

	Many of the functions in aper seem to have duplicate code taken
	from other (similar) functions.  This is semi-deliberate, just in
	case semantics change, then we can thwart brittle dependencies. :-)
	(OK, I'm lazy, but I work hard at it.)

[e] BASIC USE

	aper adds bulk data to the "phishing_reply_addresses",
	"phishing_links", and "phishing_cleared_addresses" lists. These
	will be called the APER files.

	aper is used in the current working directory.	This means you can
	copy APER files to some directory then run aper in that directory
	without affecting the original, if desired.

	aper needs two sources of data: the APER files and from the user.
	The user files can be empty.

	aper does not subtract from the APER or user files unless there
	are duplicate entries.

	aper operates on APER files based on a command line argument.
	Generically, aper is run one of two ways:

		aper list_type userdata
		aper list_type < userdata

	where list_type is:

		'reply' to add to phishing_reply_addresses
		'links' to add to phishing_links
		'cleared' to add to phishing_cleared_addresses

	and userdata is a file (or stdin) containing the same kind of data
	specified by list_type .

	Data is added to the list in a simple way.  If the entry doesn't
	exist, add it.	If its date is newer than the one in the list,
	update the date.  In the case of the phishing_reply_addresses list,
	the address type is merged with existing ones, even if the entry
	date in the userdata is older than the APER entry.

	There is some simple data validation.

	For all lists, valid dates are of the form YYYYMMDD and its
	components must resolve to a valid date using mktime().  That means
	valid dates are somewhere between 13 Dec 1901 and 19 Jan 2038.

	Each list type has it's own sense of a valid address.

	For the phishing_reply_addresses and phishing_cleared_addresses
	lists, a valid address must look like an email address; basically,
	'something@more.here'.	The address cannot have a trailing '.' and
	the host portion must begin with an alphanumeric, per RFCs.

	For the phishing_links lists, a valid address must look like a
	hostname; basically, 'some.thing.more'.  The same simple RFC check
	is done as in the above.  Further, the address cannot begin with
	'http:' or 'https:'.

	In all address checks a simple typo check is done to catch '..'.

	aper will exit with a nonzero status and a diagnostic upon data
	validation problems and not affect the APER files.  New APER files
	are written only when there are no validation or other errors.

	Sometimes this is useful:

		echo | aper list_type

	This does data validation on the APER list then writes it if
	all goes well, including removing duplicate entries or merging
	address info if the entries we made manually.

	Big Question:  How are entries removed from a list?

	Answer:  Your favorite text editor, except for the
	phishing_reply_addresses list since entries can be removed
	by adding to the phishing_cleared_addresses list though the
	editor approach works, too.

[f] Warranty and things beyond anyone's control or vision....

### This program is free software; you can redistribute it and/or
### modify it under the terms of the GNU General Public License
### as published by the Free Software Foundation; either version 2
### of the License, or (at your option) any later version.
###
### This program is distributed in the hope that it will be useful,
### but WITHOUT ANY WARRANTY; without even the implied warranty of
### MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
### GNU General Public License for more details.

Copyright (C) 2010 University of Minnesota.  All rights reserved.
*/

#include <iostream>
#include <fstream>
#include <string>
#include <list>
#include <map>
#include <set>
#include <sstream>
#include <bitset>
#include <cctype>
#include <cstdlib>
#include <time.h>
#include <cstdio>

const std::string replyfile			= "phishing_reply_addresses";
const std::string replyclearedfile	= "phishing_cleared_addresses";
const std::string linksfile			= "phishing_links";

const char tokcomment = '#';
const char tokcsv = ',';
const char toksplit = ' ';

const char *tmpdir = ".";	// dir for temp files, should be current working dir
const char *tmpprefix = ".aper";  // prefix for temp files (5 char max)

enum errstate
{
	EOK,		// all ok
	EUSE,		// usage
	EFILE,		// cannot open file of new addresses
	ERFILE,		// cannot open file of reply addresses
	ECFILE,		// cannot open file of cleared addresses
	ELFILE,		// Cannot open file of links
	EXFILE,		// cannot open temporary file
	EXFILERM,	// cannot remove temporary file
	EATYPE,		// incorrect address type
	EADDRESS,	// bad address format
	EDATE,		// bad date format
	EAPERDB,	// cannot load APER database
	EUSERDB,	// cannot load user database
	EWAPERDB,	// cannot write APER database
	EMEM,		// cannot allocate node memory for database entry
	EUNKNOWN	// we shouldn't need this, but...
};

enum trimspec
{
	ENDS,		// trim leading and trailing whitespace
	ALL			// nuke all whitespace
};

enum datamode { reply, links, cleared, nummodes };
std::bitset<nummodes> dbmode; 



class APERnode
{
public:
	APERnode( void );
	APERnode( std::string date );

	inline std::string date( void ) const { return ( _date ); }
	bool date( std::string d );
	bool isvaliddate( std::string d ) const;
	inline bool isnewer( std::string d ) const { return ( _date < d ); }

	virtual bool address( std::string a ) = 0;

private:
	std::string _date;
};

typedef std::set<char> AddrT;

class APERreply : public APERnode
{
public:
	APERreply( void );

	std::string address( void ) const;
	bool address( std::string a );
	bool isvalidaddress( std::string a ) const;

	std::string addrtype( void ) const;
	bool addrtype( std::string addrt );
	bool isvalidaddrtype( std::string addrt ) const;

	inline void clear( void ) { _iscleared = true; }
	inline bool iscleared( void ) const { return _iscleared; }

private:
	std::string _address;
	AddrT _addrt;
	bool _iscleared;
};

class APERlinks : public APERnode
{
public:
	APERlinks( void );

	std::string address( void ) const;
	bool address( std::string a );
	bool isvalidaddress( std::string address );

private:
	std::string _address;
};

class APERcleared : public APERnode
{
public:
	APERcleared( void );

	std::string address( void ) const;
	bool address( std::string a );
	bool isvalidaddress( std::string address );

private:
	std::string _address;
};

typedef std::map<std::string, APERnode *> APERdb;
typedef std::list<std::string> Comments;

std::string trimspace( std::string s, trimspec trim = ENDS );
std::string split( std::string s, char c = tokcsv );
errstate errnotify( errstate err, std::string extrainfo = "" );

bool loadaperdb( void );
bool loadaperreply( std::istream *f );
bool loadapercleared( std::istream *f );
bool loadaperlinks( std::istream *f );
bool setapercleared( std::istream *f );

bool loaduserdb( std::string datafile );
bool loaduserreply( std::istream *f );
bool loadusercleared( std::istream *f );
bool loaduserlinks( std::istream *f );

bool writeaperdb( void );

APERdb aperdb;
Comments comments;



/////////////////////////////////////////////////////
//      main                                       //
/////////////////////////////////////////////////////

int main( int argc, char *argv[] )
{
	std::string datafile;

	while ( --argc > 0 )
	{
		std::string opt = *++argv;

		if ( dbmode.none() && opt == "help" ) { return errnotify( EUSE ); }

		if ( dbmode.none() && opt == "cleared" ) { dbmode.set( cleared ); continue; }
		if ( dbmode.none() && opt == "links" ) { dbmode.set( links ); continue; }
		if ( dbmode.none() && opt == "reply" ) { dbmode.set( reply ); continue; }

		if ( dbmode.any() ) { datafile = opt; break; }
	}

	if ( dbmode.none() ) return ( errnotify( EUSE ) );

	if ( ! loadaperdb() ) return ( errnotify( EAPERDB ) );
	if ( ! loaduserdb( datafile ) ) return ( errnotify( EUSERDB ) );
	if ( ! writeaperdb() ) return ( errnotify( EWAPERDB ) ); 

	return ( EOK );
}

/////////////////////////////////////////////////////
//      errnotify                                  //
/////////////////////////////////////////////////////

errstate errnotify( errstate err, std::string extrainfo )
{
	std::string msg;

	switch ( err )
	{
		case EUSE:
			msg =
				"Add bulk to Anti Phishing Email Reply list data\n" \
				"use: aper list [file]\n" \
				"\t'list' reply | cleared | links\n" \
				"\t'file' data to add, read stdin if not specified";
			break;

		case EFILE:		msg = "Cannot open new data file"; break;
		case ERFILE:	msg = "Cannot open reply address file"; break;
		case ECFILE:	msg = "Cannot open cleared address file"; break;
		case EXFILE:	msg = "Cannot open temporary file"; break;
		case EXFILERM:	msg = "Cannot remove temporary file"; break;
		case EATYPE:	msg = "Bad record type"; break;
		case EADDRESS:	msg = "Bad address format"; break;
		case EDATE:		msg = "Bad date format"; break;
		case EAPERDB:	msg = "Cannot load APER database"; break;
		case EUSERDB:	msg = "Cannot load user database"; break;
		case EWAPERDB:	msg = "Cannot write APER database"; break;
		case EMEM:		msg = "Cannot allocate memory for entry"; break;
		case ELFILE:	msg = "Cannot open links file"; break;
	}

	if ( ! extrainfo.empty() )
		msg += ": " + extrainfo;

	std::cerr << msg << std::endl;

	return ( err );
}

/////////////////////////////////////////////////////
//      loadaperdb                                 //
/////////////////////////////////////////////////////

bool loadaperdb( void )
{
	if ( dbmode.test( reply ) )
	{
		bool r(true), c(true);

		std::ifstream ifsreply( replyfile.c_str() );
		if ( ! ifsreply ) { errnotify( ERFILE, replyfile ); return ( false ); }
		r = loadaperreply( &ifsreply );
		ifsreply.close();

		std::ifstream ifsclear( replyclearedfile.c_str() );
		if ( ! ifsclear ) { errnotify( ECFILE, replyclearedfile ); return ( false ); }
		c = setapercleared( &ifsclear );
		ifsclear.close();

		return ( r & c );
	}

	if ( dbmode.test( links ) )
	{
		std::ifstream ifs( linksfile.c_str() );
		if ( ! ifs ) { errnotify( ELFILE, linksfile ); return ( false ); }
		bool status = loadaperlinks( &ifs );
		ifs.close();

		return ( status );
	}

	if ( dbmode.test( cleared ) )
	{
		std::ifstream ifs( replyclearedfile.c_str() );
		if ( ! ifs ) { errnotify( ECFILE, replyclearedfile ); return ( false ); }
		bool status = loadapercleared( &ifs );
		ifs.close();

		return ( status );
	}

	return ( false );
}

/////////////////////////////////////////////////////
//      loadaperreply                              //
/////////////////////////////////////////////////////

bool loadaperreply( std::istream *f )
{
	std::string s;
	bool skipcomment = false;

	while ( getline( *f, s ) )
	{
		s = trimspace( s, ENDS );
		if ( s.empty() ) continue;

		if ( s[0] == tokcomment )
		{
			if ( ! skipcomment ) comments.push_back( s );
		}
		else
		{
			skipcomment = true;
			errstate err = EOK;
			std::string address, addrt, date;

			std::istringstream iss( split( s ) );
			iss >> address >> addrt >> date;

			APERreply *node = new APERreply;
			if ( ! node )
			{
				errnotify( EMEM );
				return ( false );
			}

			if ( ! node->address( address ) ) err = errnotify( EADDRESS, address );
			if ( ! node->addrtype( addrt ) ) err = errnotify( EATYPE, addrt );
			if ( ! node->date( date ) ) err = errnotify( EDATE, date );

			if ( err != EOK )
			{
				free( node );
				return ( false );
			}

			if ( aperdb.count( address ) == 0 )
			{
				aperdb[ address ] = node;
			}
			else
			{
				free( node );

				if ( aperdb[ address ]->isnewer( date ) )
					aperdb[ address ]->date( date );

				APERreply *p = dynamic_cast<APERreply *>( aperdb[ address ] );
				if ( p->addrtype() != addrt ) p->addrtype( addrt );
			}
		}
	}

	return ( true );
}

/////////////////////////////////////////////////////
//      setapercleared                             //
/////////////////////////////////////////////////////
// this is a little different from loadapercleared() in that this simply
// sets the cleared flag.  this should be called after loadaperreply().

bool setapercleared( std::istream *f )
{
	std::string s;

	while ( getline( *f, s ) )
	{
		s = trimspace( s, ENDS );
		if ( s.empty() ) continue;
		if ( s[0] == tokcomment ) continue;

		std::string address, date;
		std::istringstream iss( split( s ) );
		iss >> address;

		if ( aperdb.count( address ) > 0 )
		{
			APERreply *p = dynamic_cast<APERreply *>( aperdb[ address ] );
			p->clear();
		}
	}

	return ( true );
}

/////////////////////////////////////////////////////
//      loadapercleared                            //
/////////////////////////////////////////////////////
// this is similar loadaperlinks().  we can use a function template here
// but that would break things if the cleared and links file sematics change.

bool loadapercleared( std::istream * f )
{
	std::string s;
	bool skipcomment = false;

	while ( getline( *f, s ) )
	{
		s = trimspace( s, ENDS );
		if ( s.empty() ) continue;

		if ( s[0] == tokcomment )
		{
			if ( ! skipcomment ) comments.push_back( s );
		}
		else
		{
			skipcomment = true;
			errstate err = EOK;
			std::string address, date;

			std::istringstream iss( split( s ) );
			iss >> address >> date;

			APERcleared *node = new APERcleared;
			if ( ! node )
			{
				errnotify( EMEM );
				return ( false );
			}

			if ( ! node->address( address ) ) err = errnotify( EADDRESS, address );
			if ( ! node->date( date ) ) err = errnotify( EDATE, date );

			if ( err != EOK )
			{
				free( node );
				return ( false );
			}

			if ( aperdb.count( address ) == 0 )
			{
				aperdb[ address ] = node;
			}
			else
			{
				free( node );

				if ( aperdb[ address ]->isnewer( date ) )
					aperdb[ address ]->date( date );
			}
		}
	}

	return ( true );
}

/////////////////////////////////////////////////////
//      loadaperlinks                              //
/////////////////////////////////////////////////////

bool loadaperlinks( std::istream *f )
{
	std::string s;
	bool skipcomment = false;

	while ( getline( *f, s ) )
	{
		s = trimspace( s, ENDS );
		if ( s.empty() ) continue;

		if ( s[0] == tokcomment )
		{
			if ( ! skipcomment ) comments.push_back( s );
		}
		else
		{
			skipcomment = true;
			errstate err = EOK;
			std::string address, date;

			std::istringstream iss( split( s ) );
			iss >> address >> date;

			APERlinks *node = new APERlinks;
			if ( ! node )
			{
				errnotify( EMEM );
				return ( false );
			}

			if ( ! node->address( address ) ) err = errnotify( EADDRESS, address );
			if ( ! node->date( date ) ) err = errnotify( EDATE, date );

			if ( err != EOK )
			{
				free( node );
				return ( false );
			}

			if ( aperdb.count( address ) == 0 )
			{
				aperdb[ address ] = node;
			}
			else
			{
				free( node );

				if ( aperdb[ address ]->isnewer( date ) )
					aperdb[ address ]->date( date );
			}
		}
	}

	return ( true );
}

/////////////////////////////////////////////////////
//      loaduserdb                                 //
/////////////////////////////////////////////////////

bool loaduserdb( std::string datafile )
{
	std::istream *f = &std::cin;
	std::ifstream ifs;

	if ( ! datafile.empty() )
	{
		ifs.open( datafile.c_str() );
		if ( ! ifs )
		{
			errnotify( EFILE, datafile );
			return ( false );
		}
		f = &ifs;
	}

	bool status = true;

	if ( dbmode.test( reply ) ) status = loaduserreply( f );
	if ( dbmode.test( links ) ) status = loaduserlinks( f );
	if ( dbmode.test( cleared ) ) status = loadusercleared( f );

	if ( *f != std::cin ) ifs.close();

	return ( status );
}

/////////////////////////////////////////////////////
//      loaduserreply                              //
/////////////////////////////////////////////////////

bool loaduserreply( std::istream *f )
{
	std::string s;

	while ( getline( *f , s ) )
	{
		s = trimspace( s, ALL );
		if ( s.empty() ) continue;
		if ( s[0] == tokcomment ) continue;
			
		errstate err = EOK;
		std::string address, addrt, date;
		
		std::istringstream iss( split( s ) );
		iss >> address >> addrt >> date;

		if ( ! address.empty() && aperdb.count( address ) > 0 )
		{
			APERreply *p = dynamic_cast<APERreply *>( aperdb[ address ] );
			if ( p->iscleared() ) continue;
		}

		APERreply *node = new APERreply;
		if ( ! node )
		{
			errnotify( EMEM );
			return ( false );
		}

		if ( ! node->address( address ) ) err = errnotify( EADDRESS, address );
		if ( ! node->addrtype( addrt ) ) err = errnotify( EATYPE, addrt );
		if ( ! node->date( date ) ) err = errnotify( EDATE, date );

		if ( err != EOK )
		{
			free( node );
			return ( false );
		}

		if ( aperdb.count( address ) == 0 )
		{
			aperdb[ address ] = node;
		}
		else
		{
			free( node );

			if ( aperdb[ address ]->isnewer( date ) )
				aperdb[ address ]->date( date );

			APERreply *p = dynamic_cast<APERreply *>( aperdb[ address ] );
			if ( p->addrtype() != addrt ) p->addrtype( addrt );
		}
	}

	return ( true );
}

/////////////////////////////////////////////////////
//      loaduserlinks                              //
/////////////////////////////////////////////////////

bool loaduserlinks( std::istream *f )
{
	std::string s;

	while ( getline( *f, s ) )
	{
		s = trimspace( s, ENDS );
		if ( s.empty() ) continue;
		if ( s[0] == tokcomment ) continue;

		errstate err = EOK;
		std::string address, date;

		std::istringstream iss( split( s ) );
		iss >> address >> date;

		APERlinks *node = new APERlinks;
		if ( ! node )
		{
			errnotify( EMEM );
			return ( false );
		}

		if ( ! node->address( address ) ) err = errnotify( EADDRESS, address );
		if ( ! node->date( date ) ) err = errnotify( EDATE, date );

		if ( err != EOK )
		{
			free( node );
			return ( false );
		}

		if ( aperdb.count( address ) == 0 )
		{
			aperdb[ address ] = node;
		}
		else
		{
			free( node );

			if ( aperdb[ address ]->isnewer( date ) )
				aperdb[ address ]->date( date );
		}
	}
		
	return ( true );
}

/////////////////////////////////////////////////////
//      loadusercleared                            //
/////////////////////////////////////////////////////
// this is similar to loaduserlinks().  we can use a function template here
// but that would break things if the cleared and links file sematics change.

bool loadusercleared( std::istream *f )
{
	std::string s;

	while ( getline( *f, s ) )
	{
		s = trimspace( s, ENDS );
		if ( s.empty() ) continue;
		if ( s[0] == tokcomment ) continue;

		errstate err = EOK;
		std::string address, date;

		std::istringstream iss( split( s ) );
		iss >> address >> date;

		APERcleared *node = new APERcleared;
		if ( ! node )
		{
			errnotify( EMEM );
			return ( false );
		}

		if ( ! node->address( address ) ) err = errnotify( EADDRESS, address );
		if ( ! node->date( date ) ) err = errnotify( EDATE, date );

		if ( err != EOK )
		{
			free( node );
			return ( false );
		}

		if ( aperdb.count( address ) == 0 )
		{
			aperdb[ address ] = node;
		}
		else
		{
			free( node );

			if ( aperdb[ address ]->isnewer( date ) )
				aperdb[ address ]->date( date );
		}
	}
		
	return ( true );
}

/////////////////////////////////////////////////////
//      writeaperdb                                //
/////////////////////////////////////////////////////
// we can refactor this into specific write functions, but that's too
// much work.

bool writeaperdb( void )
{
	const char *tmpfile = tempnam( tmpdir, tmpprefix );

	std::ofstream ofs( tmpfile );
	if ( ! ofs )
	{
		errnotify( EXFILE, tmpfile );
		return ( false );
	}

	for ( Comments::iterator itr = comments.begin(); itr != comments.end(); ++itr )
	{
		ofs << *itr << std::endl;
	}

	std::string s;

	for ( APERdb::iterator itr = aperdb.begin(); itr != aperdb.end(); ++itr )
	{
		if ( APERreply *q = dynamic_cast<APERreply *>( itr->second ) )
		{
			if ( q->iscleared() ) continue;
			s = q->address() + tokcsv + q->addrtype() + tokcsv + q->date();
		}

		if ( APERlinks *q = dynamic_cast<APERlinks *>( itr->second ) )
			s = q->address() + tokcsv + q->date();

		if ( APERcleared *q = dynamic_cast<APERcleared *>( itr->second ) )
			s = q->address() + tokcsv + q->date();

		if ( ! s.empty() ) ofs << s << std::endl;
	}

	ofs.close();

	if ( dbmode.test( reply ) ) s = replyfile;
	if ( dbmode.test( links ) ) s = linksfile;
	if ( dbmode.test( cleared ) ) s = replyclearedfile;

	if ( rename( tmpfile, s.c_str() ) != 0 )
	{
		errnotify( EWAPERDB, s );
		if ( unlink( tmpfile ) != 0 ) errnotify( EXFILERM, tmpfile );
		return ( false );
	}

	return ( true );
}

/////////////////////////////////////////////////////
//      APERnode::APERnode                         //
/////////////////////////////////////////////////////

APERnode::APERnode( std::string d )
{
	date( d );
}

APERnode::APERnode( void ) {}

/////////////////////////////////////////////////////
//      APERnode::isvaliddate                      //
/////////////////////////////////////////////////////
// a valid date has the form YYYYMMDD consisting of all digits.
// valid formats are strings in the set (00000000, 99999999] and
// evalute to a valid date for the system.
//
// valid dates are between 20:45:52  UTC,  December  13,  1901
// and 03:14:07 UTC,  January 19, 2038 .

bool APERnode::isvaliddate( std::string date ) const
{
	if ( date.empty() ) return ( false );
	if ( date.size() != 8 ) return ( false );

	std::string Y = date.substr( 0, 4 );
	std::string M = date.substr( 4, 2 );
	std::string D = date.substr( 6, 2 );

	std::string digits = "0123456789";
	if ( Y.find_first_not_of( digits ) != std::string::npos ) return ( false );
	if ( M.find_first_not_of( digits ) != std::string::npos ) return ( false );
	if ( D.find_first_not_of( digits ) != std::string::npos ) return ( false );

	int y = atoi( Y.c_str() );
	int m = atoi( M.c_str() );
	int d = atoi( D.c_str() );

	if ( y * m * d == 0 ) return ( false );

	struct tm t;

	t.tm_year = y - 1900;
	t.tm_mon = m - 1;
	t.tm_mday = d;
	t.tm_hour = 0;
	t.tm_min = 0;
	t.tm_sec = 1;
	t.tm_isdst = -1;

	return ( mktime( &t ) != -1 ); 
}

/////////////////////////////////////////////////////
//      APERnode::date                             //
/////////////////////////////////////////////////////

bool APERnode::date( std::string d )
{
	return ( isvaliddate( d ) ? _date = d, true : false );
}

/////////////////////////////////////////////////////
//      APERreply::APERreply                       //
/////////////////////////////////////////////////////

APERreply::APERreply( void )
{
	_iscleared = false;
}

/////////////////////////////////////////////////////
//      APERreply::isvalidaddress                  //
/////////////////////////////////////////////////////
// lame check of email address format.
// basically, something@more.here ==> good format.
// there are no RFC-compliant checks (except one).

bool APERreply::isvalidaddress( std::string address ) const
{
	if ( address.empty() ) return ( false );

	const char tokmail = '@';
	const char tokdns = '.';

	std::string::size_type d = address.find( tokmail );

	if ( d == std::string::npos ) return ( false );

	if ( d > 0 && d < address.size() - 1 )
	{
		std::string host = address.substr( d );

		d = host.find( tokdns );
		if ( d == std::string::npos ) return ( false );

// try catching a typo...
		if ( host.find( ".." ) != std::string::npos ) return ( false );

// assume host looks like @xxxx.yyyy with '@' at position 0.
// we don't want tokdns at 0 or 1 or at the end.

		if ( d > 1 && d < host.size() - 1 )
		{
// if we got this far then there is something after tokmail
// RFC1123 and RFC952 specify host names start with a letter or digit.
			if ( ! isalnum( host.at( 1 ) ) ) return ( false );

			if ( host.at( host.size() - 1 ) != tokdns ) return ( true );
		}
	}

	return ( false );
}

/////////////////////////////////////////////////////
//      APERreply::address                         //
/////////////////////////////////////////////////////

std::string APERreply::address( void ) const
{
	return ( _address );
}

bool APERreply::address( std::string a )
{
	return ( isvalidaddress( a ) ? _address = a, true : false );
}

/////////////////////////////////////////////////////
//      APERreply::addrtype                        //
/////////////////////////////////////////////////////

std::string APERreply::addrtype( void ) const
{
	AddrT::iterator itr = _addrt.begin();
	AddrT::iterator itrE = _addrt.end();
	std::string s;

	while ( itr != itrE )
		s += *itr++;

	return ( s );
}

bool APERreply::addrtype( std::string addrt )
{
	if ( ! isvalidaddrtype( addrt ) ) return ( false );

	std::string::iterator itr = addrt.begin();
	std::string::iterator itrE = addrt.end();

	while ( itr != itrE )
	{
		_addrt.insert( std::toupper( *itr ) );
		++itr;
	}

	return ( true );
}

/////////////////////////////////////////////////////
//      APERreply::isvalidaddrtype                 //
/////////////////////////////////////////////////////

bool APERreply::isvalidaddrtype( std::string addrt ) const
{
	if ( addrt.empty() ) return ( false );

	std::string t = "ABCDEabcde";

	return ( !( addrt.find_first_not_of( t ) != std::string::npos) );
}

/////////////////////////////////////////////////////
//      APERlinks::APERlinks                       //
/////////////////////////////////////////////////////

APERlinks::APERlinks( void ) {}

/////////////////////////////////////////////////////
//      APERlinks::address                         //
/////////////////////////////////////////////////////

std::string APERlinks::address( void ) const
{
	return ( _address );
}

bool APERlinks::address( std::string a )
{
	return ( isvalidaddress( a ) ? _address = a, true : false );
}

/////////////////////////////////////////////////////
//      APERlinks::isvalidaddress                  //
/////////////////////////////////////////////////////
// lame check of web host address.  full URL not validated in any way.
// basically, some.thing.more ==> good format.
// there are no RFC-compliant checks (except one).

bool APERlinks::isvalidaddress( std::string address )
{
	if ( address.empty() ) return ( false );

	if ( address.find( "http:" ) == 0 ) return ( false );
	if ( address.find( "https:" ) == 0 ) return ( false );

// RFC1123 and RFC952 specify host names start with a letter or digit.
	if ( ! isalnum( address[0] ) ) return ( false );

	const char tokdns = '.';

	std::string::size_type d = address.find( tokdns );
	if ( d == std::string::npos ) return ( false );

// try catching a typo...
	if ( address.find( ".." ) != std::string::npos ) return ( false );

	if ( d > 0 && d < address.size() - 1 )
		if ( address.at( address.size() - 1 ) != tokdns ) return ( true );

	return ( false );
}

/////////////////////////////////////////////////////
//      APERcleared::APERcleared                   //
/////////////////////////////////////////////////////

APERcleared::APERcleared( void ) {}

/////////////////////////////////////////////////////
//      APERcleared::address                       //
/////////////////////////////////////////////////////

bool APERcleared::address( std::string a )
{
	return ( isvalidaddress( a ) ? _address = a, true : false );
}

std::string APERcleared::address( void ) const
{
	return ( _address );
}

/////////////////////////////////////////////////////
//      APERcleared::isvalidaddess                 //
/////////////////////////////////////////////////////

bool APERcleared::isvalidaddress( std::string address )
{
	APERreply n;

	return ( n.isvalidaddress( address ) );
}

/////////////////////////////////////////////////////
//      trimspace                                  //
/////////////////////////////////////////////////////
// no cleverness here, just plain brute force trimming.

std::string trimspace( std::string s, trimspec trim )
{
	if ( s.empty() ) return ( s );

	switch ( trim )
	{
		case ALL:
		{
			std::string::iterator itr = s.begin();
			std::string::iterator itrE = s.end();
			std::string t;

			while ( itr != itrE )
			{
				if ( ! isspace( *itr ) ) t += *itr;
				++itr;
			}

			s = t;
		}
			break;

		case ENDS:
		{
			std::string::iterator itr = s.begin();
			std::string::iterator itrE = s.end();

			while ( itr != itrE )
			{
				if ( ! isspace( *itr ) ) break;
				++itr;
			}

			if ( itr == itrE ) break;

			std::string t = s.substr( s.find( *itr ) );

			std::string::reverse_iterator ritr = t.rbegin();
			std::string::reverse_iterator ritrE = t.rend();

			while ( ritr != ritrE )
			{
				if ( ! isspace( *ritr ) ) break;
				++ritr;
			}

// at this point the reverse iterator must be pointing to
// a non-space char since the earlier while() stopped at one.

			t.resize( t.find_last_of( *ritr ) + 1 );
			s = t;
		}
			break;
	}

	return ( s );
}

/////////////////////////////////////////////////////
//      split                                      //
/////////////////////////////////////////////////////
// not as powerful as the perl split, but it does what we need.

std::string split( std::string s, char c )
{
	s = trimspace( s, ALL );

	std::string::iterator itr = s.begin();
	std::string::iterator itrE = s.end();

	while ( itr != itrE )
	{
		if ( *itr == c ) *itr = toksplit;
		++itr;
	}

	return ( s );
}
