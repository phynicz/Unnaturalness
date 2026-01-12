from transformers import AutoTokenizer, AutoModelForCausalLM
from PIL import Image
import requests
import torch
import os
from huggingface_hub import login
import pandas as pd
import argparse



system  = """ You have deep expertise and knowledge in the Java Programming Language and all libraries and APIs available in Java. You possess strong skills in analyzing and explaining cryptographic-API misuse that leads to vulnerabilities, ensuring a low rate of false negatives. As a highly experienced Android security analyst, your task is to find evasive cryptographic-API misuse or crypto backdoors that are often missed by security tools and manual code reviews.

Answer consisely and only respond in JSON format as shown below:
```json
{
}
"""

query= """Instructions:
1. I will provide you with code snippets that have been manually curated from several classes and method calls. This code shows that developers are using crypto backdoors in their software and it is constructed in a way that security tools will not be able to detect them.

2. BACKDOOR - CODE SNIPPET:

{```java    
private static final String KEY_AES = "AES";
private static final String KEY_CIPHER = "AES/GCM/NoPadding";
public static final String KEY_GCM = "OGEseetime201800";
private static String TAG = "AES2Utils";

algorithmStr_encode = "32Bi2A5oaH61xilScou92x9faAiO0SOBXmb0X/wqAijapt8K"
String AES_ECB_PADDING_encode = "32Bi2A5oaH6r4jpgI7+10Rwi6u+aWTgnrWUjLeHbiJK5";

Cipher.getInstance(decode(algorithmStr_encode));
Cipher.getInstance(decode(AES_ECB_PADDING_encode);

public static String decode(String str) {
 try {
  return str.isEmpty() ? "" : new String(decrypt(getbase64ToBytes(str), KEY_GCM)); //Calls the function below with Base64.getDecode().decode
 } catch (Exception e) {
  e.printStackTrace();
 return ;
}
}

public static byte[] decrypt(byte[] bArr, String str) {
 try {
  SecretKeySpec secretKeySpec = new SecretKeySpec(getKey(KEY_GCM), KEY_AES);
  byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
  Cipher cipher = Cipher.getInstance(KEY_CIPHER);
  cipher.init(2, secretKeySpec, new GCMParameterSpec(128, bytes));
 return cipher.doFinal(bArr);
 } catch (Exception e) {
  e.printStackTrace();
 return new byte[0];
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

6. IF NOT CONDITION: reply with the following:
```json
{
Conditions not met
}

7. Here is the cipher.getinstance invocation:
```java

"""


app = []

ext = ".java"

column = ['class_path','method_declaration','length_input_tokens','length_output_tokens','misuse_output']

df = pd.DataFrame(columns=column)


model_id = "/hugging_face/QwQ-32B"

tokenizer = AutoTokenizer.from_pretrained(model_id)
model = AutoModelForCausalLM.from_pretrained(
    model_id,
    device_map="auto",
    torch_dtype="auto",
)


df1 = pd.read_csv('cipher_method_new.csv')
result_dict = zip(df1['class_path'], df1['invocation'], df1['argument_list'])
size = len(list(result_dict))
print(f"This is the length of elements: \n {size}")


def get_app_id(path):
    for dir in os.listdir(path):
        app_cipher = os.path.join(path, dir)
        for root, dirs, files in os.walk(app_cipher, topdown=True, onerror=None, followlinks=True):
            app_id = os.path.basename(app_cipher)
            for filename in files:
                if ext in filename:
                    class_path = os.path.join(app_cipher, filename)
                    class_name = filename
                    app.clear()
                    with open(class_path, 'rb')  as file:
                        source_code = file.read()
                        app.append(app_id)
                        app.append(class_path)
                        app.append(class_name)
                        check_source(source_code)


def process_invocation():
    for cpath, inv, args  in  zip(df1['class_path'], df1['method_declaration'], df1['argument_list']):
        app.append(cpath)
        app.append(inv)
        check_source(inv)

def check_source(source_code):
    prompt=f"{query}{source_code}```"
    
    messages = [
    {
        "role": "system",
        "content": system
    },
    {
        "role": "user",
        "content": prompt
    }
]

    inputs = tokenizer.apply_chat_template(
	messages,
	add_generation_prompt=True,
	tokenize=True,
	return_dict=True,
	return_tensors="pt",
    ).to(model.device)
    input_ids = inputs["input_ids"][0]
    num_prompt_tokens = len(input_ids)
    app.append(num_prompt_tokens)
    outputs = model.generate(**inputs, max_new_tokens=2048)
    output_shape = outputs.shape[-1]
    num_output_tokens = outputs.shape[-1] - num_prompt_tokens
    app.append(num_output_tokens)
    current_misuse = tokenizer.decode(outputs[0][inputs["input_ids"].shape[-1]:])
    app.append(current_misuse)
    print(current_misuse)
    df.loc[len(df)] = app
    print(app)
    app.clear()



if __name__ == "__main__":
    parser_cli = argparse.ArgumentParser(description="Extract Cipher.getInstance calls from Java projects.")
    parser_cli.add_argument("output_csv", help="Path to save the output CSV")
    args = parser_cli.parse_args()
    process_invocation()
    df.to_csv(args.output_csv, index=False)
    print(f"Saved to {args.output_csv}")
