from argparse import ArgumentParser, RawTextHelpFormatter
from sys import exit
from textwrap import dedent

import modules.validate as validate
import modules.vt_api as api


if __name__ == '__main__':
    validate.api_key()
    parser =  ArgumentParser(formatter_class=RawTextHelpFormatter, description=dedent('''\
        Execute API calls to the VirusTotal API using your own API key stored in .env.
        
        Info: https://github.com/thisisgloom/virustotal
        Python: v3
        Credentials: API key from a registerd https://virustotal.com account

        '''))
    
    subparsers = parser.add_subparsers(dest='command', help='get VirusTotal information about a FILE, HASH, or URL')
    file = subparsers.add_parser('file', formatter_class=RawTextHelpFormatter)
    hash = subparsers.add_parser('hash', formatter_class=RawTextHelpFormatter)
    url = subparsers.add_parser('url', formatter_class=RawTextHelpFormatter)
    
    method_help = dedent('''\
                                   flagged: check if flagged by AV vendors
                                   comments: returns a summary for the top 30 comments
                                   votes: return the vote count 
                                   
                                   ''')
    
    file.add_argument('DATA', help=dedent('''\
                                   path to file
                                   '''))
    file.add_argument('-m', '--method', help=method_help)
    hash.add_argument('DATA', help=dedent('''\
                                   md5, sha1, or sha256 file hash
                                   '''))
    hash.add_argument('-m', '--method', help=method_help)
    url.add_argument('DATA', help=dedent('''\
                                   url 
                                   '''))
    url.add_argument('-m', '--method', help=method_help)
    args = parser.parse_args()

    if (not args.command) or (not args.method) or (not args.DATA):
        parser.print_help()
        exit(0)

    if args.method.lower() not in ['flagged', 'comments', 'votes']:
        print('\nInvalid method entered.\n')
        exit(1)

    if args.command == 'file':
        hash = validate.file(args.DATA)
        args.DATA = hash
    elif args.command == 'hash':
        validate.hash(args.DATA)
    elif args.command == 'url':
        validate.url(args.DATA)

    command = args.command.upper()
    input = args.DATA.upper()

    if args.method == 'flagged':
        positive, total = api.flagged(args.DATA, args.command)
        if positive:
            print(f'\n{command} {input}\n\tFlagged by {positive}/{total} AV vendors.\n')
        else:
            print(f'\n{command} {input}\n\tNot flagged by any AV vendors on VirusTotal.\n')
    elif args.method == 'comments':
        results = api.comments(args.DATA, args.command)
        if results:
            print(f'\n{command} {input}\n')
            for idx,result in enumerate(results[0], 1):
                print(f'COMMENT {idx}:\n\t{result}...\n')
        else:
            print(f'\n{command} {input}\n\tNo comments on VirusTotal.\n')  
    elif args.method == 'votes':
        results = api.votes(args.DATA, args.command)
        if results:
            print(f'\n{command} {input}\n\tClassified by the VirusTotal community as {results[0]} with a vote of {results[1]}.\n')
        else:
            print(f'\n{command} {input}\n\tNo votes on VirusTotal.\n')

