# CLI Reference

The main CLI entry point is `examples/extraction.py`, powered by Typer.

## Usage

```bash
python examples/extraction.py \
  --data-dir assets/sample_pcaps \
  --out-dir temp/my_output \
  --temp-dir temp/my_temp \
  --num-processes 2 \
  --write-array --write-image \
  --hours-to-subtract 3 \
  --min-labeled-pkts 5 \
  --max-labeled-pkts 100
```

See `python examples/extraction.py --help` for all options.
