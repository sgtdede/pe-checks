from capa.main import *
from capa.render.default import *
import logging
logger = logging.getLogger("capa")

def render_custo_doc(doc):
    ostream = rutils.StringIO()

    render_attack(doc, ostream)
    ostream.write("\n")
    render_mbc(doc, ostream)
    ostream.write("\n")
    render_capabilities(doc, ostream)

    return ostream.getvalue()


def render_custo(meta, rules: RuleSet, capabilities: MatchResults) -> str:
    doc = capa.render.result_document.convert_capabilities_to_result_document(meta, rules, capabilities)
    return render_custo_doc(doc)

def mainowar(argv=None):
    if sys.version_info < (3, 6):
        raise UnsupportedRuntimeError("This version of capa can only be used with Python 3.6+")

    if argv is None:
        argv = sys.argv[1:]

    desc = "The FLARE team's open-source tool to identify capabilities in executable files."
    epilog = textwrap.dedent(
        """
        By default, capa uses a default set of embedded rules.
        You can see the rule set here:
          https://github.com/fireeye/capa-rules
        To provide your own rule set, use the `-r` flag:
          capa  --rules /path/to/rules  suspicious.exe
          capa  -r      /path/to/rules  suspicious.exe
        examples:
          identify capabilities in a binary
            capa suspicious.exe
          identify capabilities in 32-bit shellcode, see `-f` for all supported formats
            capa -f sc32 shellcode.bin
          report match locations
            capa -v suspicious.exe
          report all feature match details
            capa -vv suspicious.exe
          filter rules by meta fields, e.g. rule name or namespace
            capa -t "create TCP socket" suspicious.exe
         """
    )

    parser = argparse.ArgumentParser(
        description=desc, epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    install_common_args(parser, {"sample", "format", "backend", "signatures", "rules", "tag"})
    parser.add_argument("-j", "--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(args=argv)
    handle_common_args(args)

    try:
        taste = get_file_taste(args.sample)
    except IOError as e:
        # per our research there's not a programmatic way to render the IOError with non-ASCII filename unless we
        # handle the IOError separately and reach into the args
        logger.error("%s", e.args[0])
        return -1

    try:
        logger.setLevel(logging.CRITICAL)
        rules = get_rules(args.rules, disable_progress=args.quiet)
        logger.setLevel(logging.WARNING)
        rules = capa.rules.RuleSet(rules)
        logger.debug(
            "successfully loaded %s rules",
            # during the load of the RuleSet, we extract subscope statements into their own rules
            # that are subsequently `match`ed upon. this inflates the total rule count.
            # so, filter out the subscope rules when reporting total number of loaded rules.
            len([i for i in filter(lambda r: "capa/subscope-rule" not in r.meta, rules.rules.values())]),
        )
        if args.tag:
            rules = rules.filter_rules_by_meta(args.tag)
            logger.debug("selected %d rules", len(rules))
            for i, r in enumerate(rules.rules, 1):
                # TODO don't display subscope rules?
                logger.debug(" %d. %s", i, r)
    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        logger.error("%s", str(e))
        return -1

    if args.format == "pe" or (args.format == "auto" and taste.startswith(b"MZ")):
        # this pefile file feature extractor is pretty light weight: it doesn't do any code analysis.
        # so we can fairly quickly determine if the given PE file has "pure" file-scope rules
        # that indicate a limitation (like "file is packed based on section names")
        # and avoid doing a full code analysis on difficult/impossible binaries.
        try:
            from pefile import PEFormatError

            file_extractor = capa.features.extractors.pefile.PefileFeatureExtractor(args.sample)
        except PEFormatError as e:
            logger.error("Input file '%s' is not a valid PE file: %s", args.sample, str(e))
            return -1
        pure_file_capabilities, _ = find_file_capabilities(rules, file_extractor, {})

        # file limitations that rely on non-file scope won't be detected here.
        # nor on FunctionName features, because pefile doesn't support this.
        if has_file_limitation(rules, pure_file_capabilities):
            # bail if capa encountered file limitation e.g. a packed binary
            # do show the output in verbose mode, though.
            if not (args.verbose or args.vverbose or args.json):
                logger.debug("file limitation short circuit, won't analyze fully.")
                return -1

    try:
        sig_paths = get_signatures(args.signatures)
    except (IOError) as e:
        logger.error("%s", str(e))
        return -1

    if (args.format == "freeze") or (args.format == "auto" and capa.features.freeze.is_freeze(taste)):
        format = "freeze"
        with open(args.sample, "rb") as f:
            extractor = capa.features.freeze.load(f.read())
    else:
        format = args.format
        should_save_workspace = os.environ.get("CAPA_SAVE_WORKSPACE") not in ("0", "no", "NO", "n", None)

        try:
            extractor = get_extractor(
                args.sample, format, args.backend, sig_paths, should_save_workspace, disable_progress=args.quiet
            )
        except UnsupportedFormatError:
            logger.error("-" * 80)
            logger.error(" Input file does not appear to be a PE file.")
            logger.error(" ")
            logger.error(
                " capa currently only supports analyzing PE files (or shellcode, when using --format sc32|sc64)."
            )
            logger.error(" If you don't know the input file type, you can try using the `file` utility to guess it.")
            logger.error("-" * 80)
            return -1

    meta = collect_metadata(argv, args.sample, args.rules, format, extractor)
    # meta = {}

    capabilities, counts = find_capabilities(rules, extractor, disable_progress=args.quiet)
    meta["analysis"].update(counts)

    if has_file_limitation(rules, capabilities):
        # bail if capa encountered file limitation e.g. a packed binary
        # do show the output in verbose mode, though.
        if not (args.verbose or args.vverbose or args.json):
            return -1

    if args.json:
        print(capa.render.json.render(meta, rules, capabilities))
    elif args.vverbose:
        print(capa.render.vverbose.render(meta, rules, capabilities))
    elif args.verbose:
        print(capa.render.verbose.render(meta, rules, capabilities))
    else:
        print(render_custo(meta, rules, capabilities))
    colorama.deinit()

    logger.debug("done.")
    return 0
