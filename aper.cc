/*
Copyright (C) 2010 University of Minnesota.  All rights reserved.
$Id: aper.cc,v 1.26 2010/07/27 17:16:32 shollatz Exp $

	aper.cc - add bulk APER formated addresses to text databases
	20090619.1532 s.a.hollatz <shollatz@d.umn.edu>

NOTES

[a] Use:
		aper list file
		aper list < file
		aper list

	where 'list' is one of the following:

		reply	-- add to phish reply list
		cleared	-- add to phish cleared list used by reply
		links	-- add to phish links list
		help	-- simple command usage

	Reads from stdin if file isn't given.  In the third use above, stdin
	is read until end-of-file is entered at the keyboard, usually 'ctrl-D'.

	Sometimes this is useful: echo | aper list

	The file format follows the "standard" APER form, one entry per line.
	The file must have the same type of contents as the specified list.

[b] Compile: c++ -s -o aper aper.cc

[c] Warranty

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

Copyright (C) 2010 University of Minnesota.  All rights reserved.
*/

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <sstream>
#include <bitset>
#include <algorithm>
#include <cctype>
#include <limits>
#include <cstdlib>
#include <time.h>
#include <cstdio>

//=================================================================
// TWEEKABLES
// in case file names and address types change. probably no need to
// change things beyond this point unless you're fixing things.

const std::string replyfile			= "phishing_reply_addresses";
const std::string replytypes		= "ABCDE";
const std::string replyclearedfile	= "phishing_cleared_addresses";
const std::string linksfile			= "phishing_links";
//=================================================================

const char tokcomment = '#';
const char tokcsv = ',';
const char toksplit = ' ';
const char tokmail = '@';
const char tokdns = '.';

const char *tmpdir = ".";	// dir for temp files
const char *tmpprefix = ".aper";  // prefix for temp files (5 char max)

enum errstate
{
	EOK,		// all ok
	EUSE,		// usage
	EFILE,		// cannot open file of new addresses
	ERFILE,		// cannot open file of reply addresses
	ECFILE,		// cannot open file of cleared addresses
	ELFILE,		// cannot open file of links
	EXFILE,		// cannot open temporary file
	EXFILERM,	// cannot remove temporary file
	EATYPE,		// incorrect address type
	EADDRESS,	// bad address format
	EDATE,		// bad date format
	EAPERDB,	// cannot load APER database
	EUSERDB,	// cannot load user database
	EWAPERDB,	// cannot write APER database
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
	virtual ~APERnode( void ) {}

	std::string date( void ) const { return ( _date ); }
	void date( std::string d ) { _date = d; }
	bool isvaliddate( std::string d ) const;

	bool isnewer( std::string d ) const;

	virtual void address( std::string a ) = 0;
	virtual std::string address( void ) const = 0;
	virtual bool isvalidaddress( std::string ) const = 0;

	virtual void write( std::ostream &f ) = 0;

private:
	std::string _date;
};

typedef std::set<char> AddrT;

class APERreply : public APERnode
{
public:
	APERreply( void );

	std::string address( void ) const { return ( _address ); }
	void address( std::string a ) { _address = a; }
	bool isvalidaddress( std::string a ) const;

	std::string addrtype( void ) const;
	void addrtype( std::string addrt );
	bool isvalidaddrtype( std::string addrt ) const;

	void clear( void ) { _iscleared = true; }
	void unclear( void ) { _iscleared = false; }
	bool iscleared( void ) const { return _iscleared; }

	void write( std::ostream &f );

private:
	std::string _address;
	AddrT _addrt;
	bool _iscleared;
};

class APERlinks : public APERnode
{
public:
	APERlinks( void );

	std::string address( void ) const { return ( _address ); }
	void address( std::string a ) { _address = a; }
	bool isvalidaddress( std::string address ) const;
	std::string cleanup( std::string url );

	void write( std::ostream &f );

private:
	std::string _address;
};

class APERcleared : public APERnode
{
public:
	APERcleared( void );

	std::string address( void ) const { return ( _address ); }
	void address( std::string a ) { _address = a; }
	bool isvalidaddress( std::string address ) const;

	void write( std::ostream &f );

private:
	std::string _address;
};

typedef std::map<std::string, APERnode *> APERdb;
typedef std::vector<std::string> Comments;
typedef unsigned int linenum_type;

std::string trimspace( std::string s, trimspec trim = ENDS );
std::string split( std::string s, char c = tokcsv );
std::string tolowercase( std::string s );
errstate errnotify( errstate err, std::string extrainfo = "", linenum_type line = 0 );

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

		if ( dbmode.none() )
		{
			if ( opt == "help" ) { return errnotify( EUSE ); }

			if ( opt == "cleared" ) { dbmode.set( cleared ); continue; }
			if ( opt == "links" ) { dbmode.set( links ); continue; }
			if ( opt == "reply" ) { dbmode.set( reply ); continue; }
		}

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

errstate errnotify( errstate err, std::string extrainfo, linenum_type line )
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
		case ELFILE:	msg = "Cannot open links file"; break;

		case EUNKNOWN:
		default:		msg = "Unknown error state"; break;
	}

	if ( ! extrainfo.empty() )
		msg += ": " + extrainfo;

	if ( line > 0 )
		std::cerr << "\tline " << line << ": ";

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
	linenum_type line = 0;

	while ( getline( *f, s ) )
	{
		++line;
		s = trimspace( s, ENDS );
		if ( s.empty() ) continue;

		if ( s[0] == tokcomment )
			comments.push_back( s );
		else
			break;
	}

	if ( f->good() )
	{
		do
		{
			if ( s[0] == tokcomment ) continue;

			s = trimspace( s, ENDS );
			if ( s.empty() ) continue;

			std::string address, addrt, date;

			std::istringstream iss( split( s ) );
				iss >> address >> addrt >> date;

			APERreply *node = new APERreply;

			errstate err = EOK;
			if ( err == EOK && ! node->isvalidaddress( address ) )
				err = errnotify( EADDRESS, address, line );
			if ( err == EOK && ! node->isvalidaddrtype( addrt ) )
				err = errnotify( EATYPE, addrt, line );
			if ( err == EOK && ! node->isvaliddate( date ) )
				err = errnotify( EDATE, date, line );

			if ( err != EOK )
			{
				delete node;
				return ( false );
			}

			address = tolowercase( address );
			node->address( address );
			node->addrtype( addrt );
			node->date( date );

			if ( aperdb.count( address ) == 0 )
			{
				aperdb[ address ] = node;
			}
			else
			{
				delete node;
	
				if ( ! aperdb[ address ]->isnewer( date ) )
					aperdb[ address ]->date( date );

				APERreply *p = dynamic_cast<APERreply *>( aperdb[ address ] );
				if ( p->addrtype() != addrt ) p->addrtype( addrt );
			}
		}
		while ( ++line, getline( *f, s ) );
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
	linenum_type line = 0;

	while ( getline( *f, s ) )
	{
		++line;
		s = trimspace( s, ENDS );
		if ( s.empty() ) continue;
		if ( s[0] == tokcomment ) continue;

		std::string address, date;
		std::istringstream iss( split( s ) );
		iss >> address >> date;

		APERreply *node = new APERreply;
		
		errstate err = EOK;
		if ( err == EOK && ! node->isvalidaddress( address ) )
			err = errnotify( EADDRESS, address, line );
		if ( err == EOK && ! node->isvaliddate( date ) )
			err = errnotify( EDATE, date, line );

		if ( err != EOK )
		{
			delete node;
			return ( false );
		}

		address = tolowercase( address );
		node->address( address );
		node->date( date );

		if ( aperdb.count( address ) > 0 )
		{
			delete node;

			if ( ! aperdb[ address ]->isnewer( date ) )
			{
				APERreply *p = dynamic_cast<APERreply *>( aperdb[ address ] );
				p->clear();
				p->date( date );
			}
		}
		else
		{
				node->clear();
				aperdb[ address ] = node;
		}
	}

	return ( true );
}

/////////////////////////////////////////////////////
//      loadapercleared                            //
/////////////////////////////////////////////////////

bool loadapercleared( std::istream *f )
{
	std::string s;
	linenum_type line = 0;

	while ( getline( *f, s ) )
	{
		++line;
		s = trimspace( s, ENDS );
		if ( s.empty() ) continue;

		if ( s[0] == tokcomment )
			comments.push_back( s );
		else
			break;
	}

	if ( f->good() )
	{
		do
		{
			if ( s[0] == tokcomment ) continue;

			s = trimspace( s, ENDS );
			if ( s.empty() ) continue;

			std::string address, date;

			std::istringstream iss( split( s ) );
			iss >> address >> date;

			APERcleared *node = new APERcleared;

			errstate err = EOK;
			if ( err == EOK && ! node->isvalidaddress( address ) )
				err = errnotify( EADDRESS, address, line );
			if ( err == EOK && ! node->isvaliddate( date ) )
				err = errnotify( EDATE, date, line );

			if ( err != EOK )
			{
				delete node;
				return ( false );
			}

			address = tolowercase( address );
			node->address( address );
			node->date( date );

			if ( aperdb.count( address ) == 0 )
			{
				aperdb[ address ] = node;
			}
			else
			{
				delete node;

				if ( ! aperdb[ address ]->isnewer( date ) )
					aperdb[ address ]->date( date );
			}
		}
		while ( ++line, getline( *f, s ) );
	}

	return ( true );
}

/////////////////////////////////////////////////////
//      loadaperlinks                              //
/////////////////////////////////////////////////////

bool loadaperlinks( std::istream *f )
{
	std::string s;
	linenum_type line = 0;

	while ( getline( *f, s ) )
	{
		++line;
		s = trimspace( s, ENDS );
		if ( s.empty() ) continue;

		if ( s[0] == tokcomment )
			comments.push_back( s );
		else
			break;
	}

	if ( f->good() )
	{
		do
		{
			if ( s[0] == tokcomment ) continue;

			s = trimspace( s, ENDS );
			if ( s.empty() ) continue;

			std::string address, date;

			std::istringstream iss( split( s ) );
			iss >> address >> date;

			APERlinks *node = new APERlinks;
			address = node->cleanup( address );

			errstate err = EOK;
			if ( err == EOK && ! node->isvalidaddress( address ) )
				err = errnotify( EADDRESS, address, line );
			if ( err == EOK && ! node->isvaliddate( date ) )
				err = errnotify( EDATE, date, line );

			if ( err != EOK )
			{
				delete node;
				return ( false );
			}

			node->address( address );
			node->date( date );

			if ( aperdb.count( address ) == 0 )
			{
				aperdb[ address ] = node;
			}
			else
			{
				delete node;

				if ( ! aperdb[ address ]->isnewer( date ) )
					aperdb[ address ]->date( date );
			}
		}
		while ( ++line, getline( *f, s ) );
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

	if ( *f != std::cin )
		ifs.close();
	else
		f->ignore( std::numeric_limits<int>::max() );

	return ( status );
}

/////////////////////////////////////////////////////
//      loaduserreply                              //
/////////////////////////////////////////////////////

bool loaduserreply( std::istream *f )
{
	std::string s;
	linenum_type line = 0;

	while ( getline( *f, s ) )
	{
		++line;
		s = trimspace( s, ALL );
		if ( s.empty() ) continue;
		if ( s[0] == tokcomment ) continue;
			
		std::string address, addrt, date;
		
		std::istringstream iss( split( s ) );
		iss >> address >> addrt >> date;

		APERreply *node = new APERreply;

		errstate err = EOK;
		if ( err == EOK && ! node->isvalidaddress( address ) )
			err = errnotify( EADDRESS, address, line );
		if ( err == EOK && ! node->isvalidaddrtype( addrt ) )
			err = errnotify( EATYPE, addrt, line );
		if ( err == EOK && ! node->isvaliddate( date ) )
			err = errnotify( EDATE, date, line );

		if ( err != EOK )
		{
			delete node;
			return ( false );
		}

		address = tolowercase( address );
		node->address( address );
		node->addrtype( addrt );
		node->date( date );

		if ( aperdb.count( address ) == 0 )
		{
			aperdb[ address ] = node;
		}
		else
		{
			APERreply *p = dynamic_cast<APERreply *>( aperdb[ address ] );

			if ( node->isnewer( p->date() ) )
			{
				if ( p->iscleared() ) p->unclear();
				p->date( date );
			}

			if ( p->addrtype() != addrt ) p->addrtype( addrt );

			delete node;
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
	linenum_type line = 0;

	while ( getline( *f, s ) )
	{
		++line;
		if ( s.empty() ) continue;
		if ( s[0] == tokcomment ) continue;

		std::string address, date;

		std::istringstream iss( split( s ) );
		iss >> address >> date;

		APERlinks *node = new APERlinks;
		address = node->cleanup( address );

		errstate err = EOK;
		if ( err == EOK && ! node->isvalidaddress( address ) )
			err = errnotify( EADDRESS, address, line );
		if ( err == EOK && ! node->isvaliddate( date ) )
			err = errnotify( EDATE, date, line );

		if ( err != EOK )
		{
			delete node;
			return ( false );
		}

		node->address( address );
		node->date( date );

		if ( aperdb.count( address ) == 0 )
		{
			aperdb[ address ] = node;
		}
		else
		{
			delete node;

			if ( ! aperdb[ address ]->isnewer( date ) )
				aperdb[ address ]->date( date );
		}
	}
		
	return ( true );
}

/////////////////////////////////////////////////////
//      loadusercleared                            //
/////////////////////////////////////////////////////

bool loadusercleared( std::istream *f )
{
	std::string s;
	linenum_type line = 0;

	while ( getline( *f, s ) )
	{
		++line;
		s = trimspace( s, ENDS );
		if ( s.empty() ) continue;
		if ( s[0] == tokcomment ) continue;

		std::string address, date;

		std::istringstream iss( split( s ) );
		iss >> address >> date;

		APERcleared *node = new APERcleared;

		errstate err = EOK;
		if ( err == EOK && ! node->isvalidaddress( address ) )
			err = errnotify( EADDRESS, address, line );
		if ( err == EOK && ! node->isvaliddate( date ) )
			err = errnotify( EDATE, date, line );

		if ( err != EOK )
		{
			delete node;
			return ( false );
		}

		address = tolowercase( address );
		node->address( address );
		node->date( date );

		if ( aperdb.count( address ) == 0 )
		{
			aperdb[ address ] = node;
		}
		else
		{
			delete node;

			if ( ! aperdb[ address ]->isnewer( date ) )
				aperdb[ address ]->date( date );
		}
	}
		
	return ( true );
}

/////////////////////////////////////////////////////
//      writeaperdb                                //
/////////////////////////////////////////////////////

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
		ofs << *itr << std::endl;

	for ( APERdb::iterator itr = aperdb.begin(); itr != aperdb.end(); ++itr )
		itr->second->write( ofs );

	ofs.close();

	std::string s;
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

APERnode::APERnode( std::string d ) : _date( d ) {}

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
//
// there is a lot of overkill here but it helps in strange ways.

bool APERnode::isvaliddate( std::string date ) const
{
	if ( date.empty() ) return ( false );
	if ( date.size() != 8 ) return ( false );

	std::string Y( date.substr( 0, 4 ) );
	std::string M( date.substr( 4, 2 ) );
	std::string D( date.substr( 6, 2 ) );

	std::string digits = "0123456789";
	if ( Y.find_first_not_of( digits ) != std::string::npos ) return ( false );
	if ( M.find_first_not_of( digits ) != std::string::npos ) return ( false );
	if ( D.find_first_not_of( digits ) != std::string::npos ) return ( false );

	int y( atoi( Y.c_str() ) );
	int m( atoi( M.c_str() ) );
	int d( atoi( D.c_str() ) );

	if ( y * m * d == 0 ) return ( false );
	if ( m < 1 || m > 12 ) return ( false );
	if ( d < 1 || d > 31 ) return ( false );

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
//      APERnode::isnewer                          //
/////////////////////////////////////////////////////
// is the node newer than the date given?

bool APERnode::isnewer( std::string date ) const
{
	if ( _date > date ) return ( true );
	if ( _date == date || _date < date ) return ( false );
}

/////////////////////////////////////////////////////
//      APERreply::APERreply                       //
/////////////////////////////////////////////////////

APERreply::APERreply( void ) : _iscleared( false ) {}

/////////////////////////////////////////////////////
//      AEPRreply::write                           //
/////////////////////////////////////////////////////

void APERreply::write( std::ostream &f )
{
	if ( ! iscleared() )
	{
		std::string s = address() + tokcsv + addrtype() + tokcsv + date();
		if ( ! s.empty() ) f << s << std::endl;
	}
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
			if ( ! isalnum( host.at( 1 ) ) )
			{
				// some hosts begin with other symbols
				std::string::size_type p = host.find_first_of( "-" );
				if ( p != 1 ) return ( false );
			}

// some may argue this violates RFCs since a host FQDN, terminating with a dot,
// is valid syntax.  while this may be true, we need to make the user aware
// by rejecting it since it could be a typo or something else. this also
// facilitates some level of sanity with entries in the database since
// 'a@b.c.' is nearly always 'a@b.c' though literally they're different and
// would result in different entries in the database.  also, the use of FQDN
// in a phish may be useful in indentifying phishware, so don't hide the fact
// in an automated cleanup.
			if ( host.at( host.size() - 1 ) != tokdns ) return ( true );
		}
	}

	return ( false );
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

void APERreply::addrtype( std::string addrt )
{
	std::string::iterator itr = addrt.begin();
	std::string::iterator itrE = addrt.end();

	while ( itr != itrE )
	{
		_addrt.insert( std::toupper( *itr ) );
		++itr;
	}
}

/////////////////////////////////////////////////////
//      APERreply::isvalidaddrtype                 //
/////////////////////////////////////////////////////

bool APERreply::isvalidaddrtype( std::string addrt ) const
{
	if ( addrt.empty() ) return ( false );

	std::transform( addrt.begin(), addrt.end(), addrt.begin(), toupper );

	return ( !( addrt.find_first_not_of( replytypes ) != std::string::npos) );
}

/////////////////////////////////////////////////////
//      APERlinks::APERlinks                       //
/////////////////////////////////////////////////////

APERlinks::APERlinks( void ) {}

/////////////////////////////////////////////////////
//      APERlinks::write                           //
/////////////////////////////////////////////////////

void APERlinks::write( std::ostream &f )
{
	std::string s = address() + tokcsv + date();
	if ( ! s.empty() ) f << s << std::endl;
}

/////////////////////////////////////////////////////
//      APERlinks::isvalidaddress                  //
/////////////////////////////////////////////////////
// lame check of web host address.  full URL not validated in any way.
// basically, some.host/more ==> good format.
// there are no RFC-compliant checks (except one).
// assumes address cleanup already done.

bool APERlinks::isvalidaddress( std::string address ) const
{
	if ( address.empty() ) return ( false );

// check for embedded URLs.
// this also catches misbehaved cut-and-pastes. :-)
	if ( address.find( "://" ) != std::string::npos ) return ( false );

// check host part of url.  at this time we don't care about the rest.

	std::string host = address;
	std::string::size_type p = address.find_first_of( "/?#" );
	if ( p != std::string::npos )
		host = address.substr( 0, p );

	if ( host.empty() ) return ( false );

	std::string::size_type d = host.find( tokdns );
	if ( d == std::string::npos ) return ( false );

// RFC1123 and RFC952 specify host names start with a letter or digit.
	if ( ! isalnum( host[0] ) )
	{
		// some hosts begin with other symbols
		std::string::size_type p = host.find_first_of( "-" );
		if ( p != 0 ) return ( false );
	}

// try catching a typo
	if ( host.find( ".." ) != std::string::npos ) return ( false );

// see FQDN discussion in APERreply::isvalidaddress()
	if ( host.at( host.size() - 1 ) != tokdns ) return ( true );

	return ( false );
}

/////////////////////////////////////////////////////
//      APERlinks::cleanup                         //
/////////////////////////////////////////////////////
// transform url to something sane. doesn't do much right now...

std::string APERlinks::cleanup( std::string url )
{
	if ( url.empty() ) return ( url );

	std::string::size_type p;

// remove scheme
// RFC3986 states the scheme can be uppercase but apps should produce
// lowercase for consistency and documents that present schemes should
// do so in lowercase.

	std::string scheme;
	std::string h( "://" );

	p = url.find( h );
	if ( p != std::string::npos )
	{
		std::string::size_type q = p + h.size();
		std::string s = tolowercase( url.substr( 0, q ) );

		// we only nuke ordinary web schemes at the beginning,
		// not embedded URLs (those found as extra info, etc).
		// address validators should flag a bad addr if :// is found.
		if ( s.find( "http" + h ) == 0 || s.find( "https" + h ) == 0 )
			url.erase( 0, q );
	}

// make host part ("authority" in RFC lingo) lowercase
// RFC3986 specifies termination chars.

	p = url.find_first_of( "/?#" );

	if ( p != std::string::npos )
	{
		for ( std::string::size_type q = 0; q < p; ++q )
			url[ q ] = tolower( url[ q ] );
	}
	else
		url = tolowercase( url );

// remove trailing slash

	std::string::reverse_iterator ritr = url.rbegin();

	if ( *ritr == '/' )
		url.resize( url.find_last_of( *ritr ) );

	return ( url );
}

/////////////////////////////////////////////////////
//      APERcleared::APERcleared                   //
/////////////////////////////////////////////////////

APERcleared::APERcleared( void ) {}

/////////////////////////////////////////////////////
//      APERcleared::write                         //
/////////////////////////////////////////////////////

void APERcleared::write( std::ostream &f )
{
	std::string s = address() + tokcsv + date();
	if ( ! s.empty() ) f << s << std::endl;
}

/////////////////////////////////////////////////////
//      APERcleared::isvalidaddess                 //
/////////////////////////////////////////////////////

bool APERcleared::isvalidaddress( std::string address ) const
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
	std::replace( s.begin(), s.end(), c, toksplit );
	return ( s );
}

/////////////////////////////////////////////////////
//      tolowercase                                //
/////////////////////////////////////////////////////

std::string tolowercase( std::string s )
{
	std::transform( s.begin(), s.end(), s.begin(), tolower );
	return ( s );
}
