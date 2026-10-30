import argparse


def main():
    parser = argparse.ArgumentParser(description="EtherNet/IP Security Framework")
    parser.add_argument('command', nargs='?', help='discover|enumerate|read|write|assess')
    parser.add_argument('target', nargs='?', help='Target IP')
    args = parser.parse_args()
    print(f'Command: {args.command} Target: {args.target}')

if __name__ == '__main__':
    main()
