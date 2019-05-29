/**
 * The problem:
 * This challenge presents the user with a webpage containing 9 buttons. The
 * user must hit the buttons in the right order to "win". The "winning"
 * functions should be called in this order:
 *
 * 1. __syscall80
 * 2. __syscall72
 * 3. __syscall42
 * 4. __syscall18
 * 5. the_end
 * 6. __syscall12
 * 7. __syscall188
 *
 * Why use the __syscall* names? WASM has a bunch of these built in and since
 * function names matter in WASM <-> JS logic, I just decided to go with names
 * that blend in.
 *
 * The answer: 1947482
 *
 * Suggested solution:
 * In theory, a 7 digit number has 9,999,999 possible combinations. However,
 * the way this is written actually breaks down to 7, largely independent, key
 * presses that have a 1/10 shot of being correct.
 *
 * Furthermore, successful keypresses *always* result in window.console.log
 * being rewritten. If the attacker is able to observe window.console.log (via
 * debug console) then they can easily determine which digits transition
 * window.console.log to a new function.
 *
 * The only anti-debug feature at the moment is the "debugger" keyword.However,
 * since that logic lives in javascript, the attacker should be able to comment
 * that out and fix up the WASM check quite easily. If you understand all of
 * this up front, this should take no more than 10 minutes to beat... presumably
 * actually reversing all this would take much more time.
 *
 *
 * Official WASM Documentation:
 * - https://webassembly.github.io/spec/core/syntax/instructions.html
 * - https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md
 *
 * Toolchain Documentation:
 * - https://emscripten.org/index.html
 *
 * Other Resources:
 * - https://i.blackhat.com/us-18/Thu-August-9/us-18-Lukasiewicz-WebAssembly-A-New-World-of-Native_Exploits-On-The-Web-wp.pdf
 * - https://www.pnfsoftware.com/reversing-wasm.pdf
 * - https://wasdk.github.io/WasmFiddle/
 *
 * Compiling WASM snippets:
 * emcc -O3 -s ONLY_MY_CODE=1 -s WASM=1 -s EXTRA_EXPORTED_RUNTIME_METHODS='["ccall"]' main.c -o main.html
 * wasm-strip main.wasm
 *
 * Modifying wat and dumping WASM to C array:
 * wasm2wat main.wasm > main.wat
 * ... write custom wat in main.wat ...
 * wat2wasm main.wat -o lol.wasm
 * xxd -i ./lol.wasm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <emscripten/emscripten.h>

// Tracks the time at which __syscall80 was visited.
static int first_press = 0;

// Stored indirect call here to be annoying
static void (*g_func_ptr)() = 0;

// Have we stored log in assert?
static int log_stored = 0;

/**
 * Executes the debugger keyword in javascript. If the console is up then it
 * will cause the program to pause and the user will have to click through. If
 * we detect this behavior, restore the default console.log
 */
static int debugger_check()
{
    int before = time(NULL);
    EM_ASM(
    {
        debugger;
    });
    int after = time(NULL);
    if ((after - before) != 0)
    {
        if (log_stored == 1)
        {
            EM_ASM(
            {
                delete window['console']['log'];
                window['console']['log'] = window['console']['assert'];
            });
        }
        return 1;
    }
    return 0;
}

/**
 * hello is the first function to execute. It fires before main(). It has three
 * key responsibilities:
 *
 * 1. Check for the developer console via the javascript debugger keyword.
 * 2. Inspect the function that executes debugger to see if its been modified.
 * 3. Overwrite console.log to point to __syscall80.
 *
 * This function is also called when the attacker fails to guess the correct
 * digit. I imagine subversion of this function would be quite bad.
 */
static void hello()
{
    // check for dev console.
    if (debugger_check() == 1)
    {
        return;
    }

    // the expected value of ASM_CONSTS[0].
    char expected[] = "function(){debugger}";

    // check to see if the debugger logic was modified
    int result = EM_ASM_INT(
    {
        var check_js = ASM_CONSTS[0].toString();
        var expected = AsciiToString($0);
        return check_js == expected;
    }, expected);

    if (result != 1)
    {
        if (log_stored == 1)
        {
            EM_ASM(
            {
                delete window['console']['log'];
                window['console']['log'] = window['console']['assert'];
            });
        }
        return;
    }

    // reset console.log
    log_stored = 1;
    EM_ASM(
    {
        window['console']['assert'] = window['console']['log'];
        window['console']['log'] = function(param)
        {
            var result = Module.ccall('__syscall80', 'void', ['number'], [param]);
        }
    });
}

/*
 * This is the first digit logic. Basically, if the first digit is 1 then
 * overwrite console.log with the next handler. Otherwise, reset using hello.
 */
static void call_me_indirectly(int p_value)
{
    if (p_value == 1)
    {
        EM_ASM(
        {
            window['console']['log'] = function(param)
            {
                var result = Module.ccall('__syscall72', 'void', ['number'], [param]);
            }
        });
    }
    else
    {
        hello();
    }
}

/*
 * This is the first digit handler. Indirectly call call_me_indirectly. Just to be
 * annoying. p_value is the value passed into "console.log"
 */
void EMSCRIPTEN_KEEPALIVE __syscall80(int p_value)
{
    // check for dev console.
    if (debugger_check() == 1)
    {
        return;
    }

    // this is the first half of my bad anti-automation logic. Basically,
    // store the time of the first keypress. Check time at later keypresses
    // to determine if the button pressing is being automated.
    first_press = time(NULL);

    // call call_me_indirectly based on index in the lookup table
    g_func_ptr(p_value);
}

/*
 * This is the second digit handler. In this one, we hold WASM byte code in
 * a javascript array. The WASM just checks the pressed key is 9. We load
 * the byte code and execute it. Simple!
 */
void EMSCRIPTEN_KEEPALIVE __syscall72(int p_value)
{
    int result = EM_ASM_INT(
    {
        /**
         * int oh_no(int p_pressed_key) {
         *     if (p_pressed_key == 9) {
         *       return 1;
         *     }
         *     return 0;
         * }
         */
        var wasm = new Uint8Array([
            0,97,115,109,1,0,0,0,1,134,128,128,128,0,1,96,1,127,1,127,3,130,
            128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,
            128,0,1,0,1,6,129,128,128,128,0,0,7,146,128,128,128,0,2,6,109,
            101,109,111,114,121,2,0,5,111,104,95,110,111,0,0,10,141,128,128,
            128,0,1,135,128,128,128,0,0,32,0,65,9,70,11
        ]);

        var module = new WebAssembly.Module(wasm);
        var module_instance = new WebAssembly.Instance(module);
        var result = module_instance.exports.oh_no($0);
        return result;
    }, p_value);

    if (result == 1)
    {
        EM_ASM(
        {
            window['console']['log'] = function(param)
            {
                var result = Module.ccall('__syscall42', 'void', ['number'], [param]);
            }
        });
    }
    else
    {
        hello();
    }
}

/*
 * This is the third digit handler. In this one, we hold WASM byte code in
 * a C array. This changes where it's stored in memory compared to the second
 * digit handler. The WASM just checks the pressed key is 4. Passing memory
 * into javascript is weird so we have to read the entire thing into a uint8array
 * before we can load and execute.
 */
void EMSCRIPTEN_KEEPALIVE __syscall42(int p_value)
{
    /*
     * int oh_no(int p_pressed_key) { 
     *  if (p_pressed_key == 4) {
     *      return 1;
     *  }
     *  return 0;
     * }
     */
    const char wasm[43] =
    {
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01, 0x60,
        0x01, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x0a, 0x01, 0x06,
        0x5f, 0x6f, 0x68, 0x5f, 0x6e, 0x6f, 0x00, 0x00, 0x0a, 0x09, 0x01, 0x07,
        0x00, 0x20, 0x00, 0x41, 0x04, 0x46, 0x0b
    };

    int result = EM_ASM_INT(
    {
        // read the C array into a uint8array
        var wasm_array = new Uint8Array($2);
        for (var i = 0; i < $2; i++)
        {
            wasm_array[i] = getValue($1 + i);
        }

        // compile and execute
        var module = new WebAssembly.Module(wasm_array);
        var module_instance = new WebAssembly.Instance(module);
        var result = module_instance.exports._oh_no($0);
        return result;
    }, p_value, wasm, 43);

    if (result == 1)
    {
        EM_ASM(
            {
                window['console']['log'] = function(param)
                {
                    var result = Module.ccall('__syscall18', 'void', ['number'], [param]);
                }
            });
    }
    else
    {
        hello();
    }
}

/*
 * This is the fourth digit handler. In this one, we hold xor obfuscated WASM
 * byte code in a C array.The C array is deobfuscated before being passed into
 * the javascript.
 */
void EMSCRIPTEN_KEEPALIVE __syscall18(int p_value)
{
    /*
     * int oh_no(int p_pressed_key) { 
     *  if (p_pressed_key == 7) {
     *      return 1;
     *  }
     *  return 0;
     * }
     */
    char wasm[97] =
    {
        170,203,217,199,171,170,170,170,171,44,42,42,42,170,171,202,
        171,213,171,213,169,40,42,42,42,170,171,170,174,46,42,42,
        42,170,171,218,170,170,175,41,42,42,42,170,171,170,171,172,
        43,42,42,42,170,170,173,56,42,42,42,170,168,172,199,207,
        199,197,216,211,168,170,175,197,194,245,196,197,170,170,160,39,
        42,42,42,170,171,45,42,42,42,170,170,138,170,235,173,236,
        161,
    };

    for (int i = 0; i < 97; i++)
    {
        wasm[i] = (wasm[i] ^ 0xaa) & 0xff;
    }

    int result = EM_ASM_INT(
    {
        // read the C array into a uint8array
        var wasm_array = new Uint8Array($2);
        for (var i = 0; i < $2; i++)
        {
            wasm_array[i] = getValue($1 + i);
        }

        // compile and execute
        var module = new WebAssembly.Module(wasm_array);
        var module_instance = new WebAssembly.Instance(module);
        var result = module_instance.exports.oh_no($0);
        return result;
    }, p_value, wasm, 97);

    if (result == 1)
    {
        EM_ASM(
        {
            window['console']['log'] = function(param)
            {
                var result = Module.ccall('the_end', 'void', ['number'], [param]);
            }
        });
    }
    else
    {
        hello();
    }
}

/*!
 *
 * This is the fifth digit handler. The attacker has gotten 4/6 digits! If the
 * attacker fails to get this one right then we'll restore console.log to its
 * normal state and execute "lol_wasm" which is just a module that uses the
 * unreachable opcode. Unreachable just triggers a runtime error. Note that
 * restoring the console affectively means the attacker can't interact with the
 * wasm code whereas the unreachable thing is just silliness.
 *
 * This code has a little false flag, "you did it" in it. That is dead code.
 *
 * This function features two WASM byte code payloads. The first is a simple
 * xor deobfuscation and the other is an xor obfuscated payload. All of that
 * is held in javascript.
 *
 * This function also does a check to see if digits are being pressed quickly.
 * I, a human person, have triggered this logic. But I've also hit the number
 * combination many many times. So I'm fine with it.
 */
void EMSCRIPTEN_KEEPALIVE the_end(int p_value)
{
    int result = 0;
    int are_you_a_bot = time(NULL);
    if ((are_you_a_bot - first_press) > 1)
    {
        result = EM_ASM_INT(
        {
            /*
            * int g_func_ptr(int test) {
            *  return test ^ 0xbb;
            * }
            */
            var xor_decode = new Uint8Array([
                0,97,115,109,1,0,0,0,1,134,128,128,128,0,1,96,
                1,127,1,127,3,130,128,128,128,0,1,0,4,132,128,
                128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,
                6,129,128,128,128,0,0,7,147,128,128,128,0,2,6,
                109,101,109,111,114,121,2,0,6,108,111,108,119,
                97,116,0,0,10,142,128,128,128,0,1,136,128,128,
                128,0,0,32,0,65,187,1,115,11
            ]);

            /*
            * int lolwat(int p_value) {
            * if (p_value == 4) {
            *   return 1;
            * }
            *   return 0;
            *}
            */
            var wasmCode = new Uint8Array([
                187,218,200,214,186,187,187,187,186,61,59,59,59,187,186,219,
                186,196,186,196,184,57,59,59,59,187,186,187,191,63,59,59,
                59,187,186,203,187,187,190,56,59,59,59,187,186,187,186,189,
                58,59,59,59,187,187,188,47,59,59,59,187,185,189,214,222,
                214,212,201,194,185,187,188,204,222,207,200,218,213,223,187,187,
                177,54,59,59,59,187,186,60,59,59,59,187,187,155,187,250,
                191,253,176
            ]);

            var xor_module = new WebAssembly.Module(xor_decode);
            var xor_instance = new WebAssembly.Instance(xor_module);

            for (var i = 0; i < wasmCode.length; i++)
            {
                wasmCode[i] = xor_instance.exports.lolwat(wasmCode[i]);
            }

            var module = new WebAssembly.Module(wasmCode);
            var module_instance = new WebAssembly.Instance(module);
            var result = module_instance.exports.wetsand($0);
            return result;
        }, p_value);
    }

    if (result == 1)
    {
        EM_ASM(
        {
            window['console']['log'] = function(param)
            {
                var result = Module.ccall('__syscall12', 'void', ['number'], [param]);
            }
        });
    }
    else
    {
        /*
         ( module           *
         ( type (;0;) (func (param i32) (*result i32)))
         (func (;0;) (type 0) (param i32) (result i32)
         unreachable)
         (export "_stage_one" (func 0)))
         */
        unsigned char __lol_wasm[43] = {
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01, 0x60,
            0x01, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x0e, 0x01, 0x0a,
            0x5f, 0x73, 0x74, 0x61, 0x67, 0x65, 0x5f, 0x6f, 0x6e, 0x65, 0x00, 0x00,
            0x0a, 0x05, 0x01, 0x03, 0x00, 0x00, 0x0b
        };
        int result = EM_ASM_INT(
        {
            try
            {
                // read the C array into a uint8array
                var wasm_array = new Uint8Array($1);
                for (var i = 0; i < $1; i++)
                {
                    wasm_array[i] = getValue($0 + i);
                }

                // restore console log. disable console error. The challenger won't
                // will need to refresh the page to get back to the WASM code.
                delete window['console']['log'];
                window['console']['log'] = window['console']['assert'];

                // compile and execute
                var module = new WebAssembly.Module(wasm_array);
                var module_instance = new WebAssembly.Instance(module);
                module_instance.exports._stage_one($0);

                // this is dead code.
                important = $2;
                alert("Whoa! You got it! Email the 7 digit code to solvedthechallenge@tenable.com");
            }
            catch(err)
            {
                // suppress error
            }
        }, __lol_wasm, 43, call_me_indirectly);
    }
}

/*
 * With two digits left there is no need to get crazy. It's a trivial brute
 * force at this point. This is some very basic bit manipulation to isolate "8"
 */
void EMSCRIPTEN_KEEPALIVE __syscall12(int p_value)
{
    if ((p_value & 0x03) == 0 && (p_value & 0x04) == 0 && (p_value >> 3) == 1)
    {
        EM_ASM(
        {
            window['console']['log'] = function(param)
            {
                var result = Module.ccall('__syscall188', 'void', ['number'], [param]);
            }
        });
    }
    else
    {
        // reset
        hello();
    }
}

/*
 * As previously stated, this is so easy to brute force that no effort really
 * needs to be made here. I've hidden the final alert in a base64'd string. It
 * reads:
 *
 * alert("Whoa! You got it! Email the 7 digit code to jbaines@tenable.com");
 */
void EMSCRIPTEN_KEEPALIVE __syscall188(int p_value)
{
    if (p_value == 2)
    {
        emscripten_run_script("eval(atob('YWxlcnQoJ0dvb2Qgam9iISBZb3UgZGlkIGl0ISBZb3VyIHByaXplIGlzIHRoZSBzYXRpc2ZhY3Rpb24gb2YgYSBqb2Igd2VsbCBkb25lLiBDb25ncmF0cyEnKTs='))");
    }

    // reset
    hello();
}

int main(int p_argc, char** p_argv)
{
    // the javascript glue invokes the script this way.
    if (p_argc != 1 || strcmp(p_argv[0], "./this.program") != 0)
    {
        EM_ASM(
        {
            delete window['console']['log'];
            window['console']['log'] = window['console']['assert'];
            exit(0);
        });
    }
    else
    {
        // "call_me_indirectly" should be at one given the current code layout.
        g_func_ptr = 1;
    }

    return EXIT_SUCCESS;
}
