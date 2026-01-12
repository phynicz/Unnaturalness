import anthropic
import requests
import os
import pandas as pd
import argparse
import time
from datetime import datetime, timedelta


#python script.py output.csv --max-rpm 50 --resume


client = anthropic.Anthropic(
    api_key=""
)

# Rate limiting configuration
MAX_REQUESTS_PER_MINUTE = 50  # Adjust based on your tier
REQUEST_TIMESTAMPS = []

system_role = """ You have deep expertise and knowledge in the Java Programming Language and all libraries and APIs available in Java. You possess strong skills in analyzing and explaining cryptographic-API misuse that leads to vulnerabilities, ensuring a low rate of false negatives. As a highly experienced Android security analyst, your task is to find evasive cryptographic-API misuse or crypto backdoors that are often missed by security tools and manual code reviews.

Answer consisely and only respond in JSON format as shown below:
```json
{
}
"""

# Static query part that will be cached
query_template = """Instructions:
1. I will provide you with code snippets that have been manually curated from several classes and method calls. This code shows that developers are using crypto backdoors in their software and it is constructed in a way that security tools will not be able to detect them.

2. BACKDOOR - CODE SNIPPET:

{```java    
    public static String m7151a(String str, String str2) {
        if (TextUtils.isEmpty(str)) {
            return null;
        }
        try {
            byte[] decode = Base64.decode(str, 0);
            SecretKeySpec secretKeySpec = new SecretKeySpec(str2.getBytes(), "AES");
            if (TextUtils.isEmpty(f8241a)) {
                f8241a = m7150a("AES/CBC/PKCS5Padding");
            }
            Cipher cipher = Cipher.getInstance(f8241a);
            cipher.init(2, secretKeySpec);
            return new String(cipher.doFinal(decode));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /* renamed from: a */
    public static String m7150a(String str) {
        int[] iArr = new int[str.length()];
        iArr[4] = 6;
        iArr[5] = 1;
        iArr[6] = 1;
        return new String(m7153a(str.getBytes(), iArr));
    }

    /* renamed from: a */
    public static byte[] m7153a(byte[] bArr, int[] iArr) {
        if (bArr == null || bArr.length == 0 || iArr == null || iArr.length == 0) {
            return bArr;
        }
        byte[] bArr2 = new byte[bArr.length];
        for (int i = 0; i < bArr.length; i++) {
            bArr2[i] = (byte) (bArr[i] ^ iArr[i % iArr.length]);
        }
        return bArr2;
    }
}
```}


3. TASK: Identify and only report identical backdoors or delibrate obfuscation. Do this by first understanding the cipher.getinstance invocation, its arguments and surrounding code context. 

4. CONDITION:
ONLY REPORT exact or close similar backdoors as shown above.

5. IF CONDITION is met: generate the following report:
{
    "Code": "Cipher.getInstance code found in prompt that is a backdoor"
    "Detailed Description": Explain in details how the invocation found is a backdoor. Show how it evades crypto-detector or security tools and manual code reviews. Explain in details what is going on in the code.
    }

6. IF NOT CONDITION: reply with exactly the following with no reasoning:
```json
{
Conditions not met
}

7. Here is the cipher.getinstance invocation:
```java
"""

labels = []
column = ['class_path', 'method_declaration', 'input_tokens', 'output_tokens', 'cache_creation_tokens', 'cache_read_tokens', 'misuse_output']
df = pd.DataFrame(columns=column)

df1 = pd.read_csv('/home/spl/victor/LLM_models/cipher_method_new.csv')


def check_rate_limit():
    """Implement rate limiting to avoid hitting API limits"""
    global REQUEST_TIMESTAMPS
    
    now = datetime.now()
    # Remove timestamps older than 1 minute
    REQUEST_TIMESTAMPS = [ts for ts in REQUEST_TIMESTAMPS if now - ts < timedelta(minutes=1)]
    
    if len(REQUEST_TIMESTAMPS) >= MAX_REQUESTS_PER_MINUTE:
        # Calculate sleep time
        oldest_timestamp = REQUEST_TIMESTAMPS[0]
        sleep_time = 60 - (now - oldest_timestamp).total_seconds()
        if sleep_time > 0:
            print(f"Rate limit reached. Sleeping for {sleep_time:.2f} seconds...")
            time.sleep(sleep_time + 1)  # Add 1 second buffer
            REQUEST_TIMESTAMPS.clear()
    
    REQUEST_TIMESTAMPS.append(now)


def load_checkpoint(output_csv):
    """Load existing progress from checkpoint file"""
    checkpoint_file = output_csv.replace('.csv', '_checkpoint.csv')
    if os.path.exists(checkpoint_file):
        try:
            checkpoint_df = pd.read_csv(checkpoint_file)
            print(f"Resuming from checkpoint: {len(checkpoint_df)} records already processed")
            return checkpoint_df, set(checkpoint_df['class_path'].tolist())
        except Exception as e:
            print(f"Error loading checkpoint: {e}")
            return pd.DataFrame(columns=column), set()
    return pd.DataFrame(columns=column), set()


def save_checkpoint(df, output_csv):
    """Save current progress to checkpoint file"""
    checkpoint_file = output_csv.replace('.csv', '_checkpoint.csv')
    try:
        df.to_csv(checkpoint_file, index=False)
    except Exception as e:
        print(f"Error saving checkpoint: {e}")


def process_invocation(output_csv):
    global df
    
    # Load checkpoint if exists
    df, processed_paths = load_checkpoint(output_csv)
    
    total_records = len(df1)
    processed_count = len(processed_paths)
    
    print(f"Total records to process: {total_records}")
    print(f"Already processed: {processed_count}")
    print(f"Remaining: {total_records - processed_count}")
    
    for idx, (cpath, inv) in enumerate(zip(df1['class_path'], df1['method_declaration'])):
        # Skip already processed records
        if cpath in processed_paths:
            continue
        
        current_idx = idx + 1
        print(f"\nProcessing {current_idx}/{total_records}: {cpath}")
        print(f"Progress: {(current_idx/total_records)*100:.1f}%")
        
        labels.append(cpath)
        labels.append(inv)
        summarize(inv)
        print(labels)
        df.loc[len(df)] = labels
        labels.clear()
        
        # Save checkpoint every 10 records
        if len(df) % 10 == 0:
            save_checkpoint(df, output_csv)
            print(f"Checkpoint saved: {len(df)} records")
        
        # Add small delay between requests
        time.sleep(0.5)
    
    # Final save
    save_checkpoint(df, output_csv)


def summarize(source_code):
    """Summarize with prompt caching enabled"""
    check_rate_limit()  # Check rate limit before making request
    
    prompt = f"{source_code}```"
    
    try:
        message = client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=1024,
            system=[
                {
                    "type": "text",
                    "text": system_role,
                    "cache_control": {"type": "ephemeral"}
                },
                {
                    "type": "text", 
                    "text": query_template,
                    "cache_control": {"type": "ephemeral"}
                }
            ],
            messages=[{"role": "user", "content": prompt}]
        )
        
        tokens = message.usage
        input_token = tokens.input_tokens
        output_token = tokens.output_tokens
        cache_creation_tokens = getattr(tokens, 'cache_creation_input_tokens', 0)
        cache_read_tokens = getattr(tokens, 'cache_read_input_tokens', 0)
        summary = message.content[0].text
        
        print(f"Tokens - Input: {input_token}, Output: {output_token}, "
              f"Cache Creation: {cache_creation_tokens}, Cache Read: {cache_read_tokens}")
        print(summary)
        
        labels.append(input_token)
        labels.append(output_token)
        labels.append(cache_creation_tokens)
        labels.append(cache_read_tokens)
        labels.append(summary)
        
    except anthropic.RateLimitError as e:
        print(f"Rate limit error: {e}")
        print("Waiting 60 seconds before retrying...")
        time.sleep(60)
        return summarize(source_code)  # Retry
        
    except Exception as e:
        print(f"Error processing request: {e}")
        labels.append(0)
        labels.append(0)
        labels.append(0)
        labels.append(0)
        labels.append(f"Error: {str(e)}")
    
    return


if __name__ == "__main__":
    parser_cli = argparse.ArgumentParser(description="Extract Cipher.getInstance calls from Java projects.")
    parser_cli.add_argument("output_csv", help="Path to save the output CSV")
    parser_cli.add_argument("--max-rpm", type=int, default=50, 
                          help="Maximum requests per minute (default: 50)")
    parser_cli.add_argument("--resume", action="store_true",
                          help="Resume from checkpoint if available")
    args = parser_cli.parse_args()
    
    MAX_REQUESTS_PER_MINUTE = args.max_rpm
    
    print(f"Starting processing with rate limit: {MAX_REQUESTS_PER_MINUTE} requests/minute")
    
    try:
        process_invocation(args.output_csv)
        df.to_csv(args.output_csv, index=False)
        print(f"\n✓ Processing complete! Saved to {args.output_csv}")
        
        # Clean up checkpoint file on successful completion
        checkpoint_file = args.output_csv.replace('.csv', '_checkpoint.csv')
        if os.path.exists(checkpoint_file):
            os.remove(checkpoint_file)
            print(f"✓ Checkpoint file removed")
            
    except KeyboardInterrupt:
        print("\n\n⚠ Process interrupted by user")
        save_checkpoint(df, args.output_csv)
        print(f"✓ Progress saved to checkpoint. Run with --resume to continue")
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        save_checkpoint(df, args.output_csv)
        print(f"✓ Progress saved to checkpoint. Run with --resume to continue")
