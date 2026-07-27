## 介绍

此库尝试通过汇编`JMP`指令实现.net中方法钩子。  
This library implement .net method hooking by using native `JMP` directive.   

## 调用方法

添加MethodHook示例（可以添加多个MethodHook）：
```
var sourceMethod = typeof(string).GetMethod("Compare", BindingFlags.Public | BindingFlags.Static, null, new Type[] { typeof(string), typeof(string) }, null);
var targetMethod = typeof(Program).GetMethod(nameof(NewCompare), BindingFlags.Public | BindingFlags.Static, null, new Type[] { typeof(string), typeof(string) }, null);
Crane.MethodHook.MethodHookManager.Instance.AddHook(new MethodHook(sourceMethod, targetMethod));
```

要让所有添加的Hook生效，请开启Hook：
```
Crane.MethodHook.MethodHookManager.Instance.StartHook();
```

Hook开启后，可以随时关闭Hook：
```
Crane.MethodHook.MethodHookManager.Instance.StopHook();
```

当前MethodHookManager设计为静态类型，碰到同一共享方法在多AppDomain进行Hook时，请确保在AppDomain切换时只保持一个AppDomain中进行Hook，其他已经Hook了的域需要进行StopHook处理，否则可能会报错。

要在新方法中调用原始方法，请先获取当前方法所绑定的MethodHook，然后可以使用`InvokeOriginal`来调用Hook前的原始方法。  

下面这个例子`string.Compare`Hook生效后，在新方法中希望调用原始的`string.Compare`方法，就可以这样：
```
public static int NewCompare(string a, string b)
{
    var methodHook = Crane.MethodHook.MethodHookManager.Instance.GetHook(System.Reflection.MethodBase.GetCurrentMethod());
    return -1 * methodHook.InvokeOriginal<int>(null,a,b); 
}
```

## 特别说明

这个库Hook时原方法和目标方法不验证签名，意思是对象的实例方法也可以Hook到一个静态方法，私有方法也可以Hook到公共方法，很无脑。  
实现方法是在定义时将静态方法的第一个参数设置为实例对象，其他参数在后面依次添加。如下示例：
```
var sourceMethod = typeof(Person).GetMethod("ShowPersonAge", BindingFlags.Public | BindingFlags.Instance, null, new Type[] { }, null);
var targetMethod = typeof(Program).GetMethod(nameof(ShowPersonAgeNew), BindingFlags.Public | BindingFlags.Static, null, new Type[] { typeof(Person) }, null);
```

```
public class Person
{
    public string Name { get; set; }
    public int Age { get; set; }

    public void ShowPersonAge()
    {
        Console.WriteLine(Name + " is " + Age.ToString() + " years old.");
    }
}

```

```
public static void ShowPersonAgeNew(Person a)
{
    if (a.Name == "John")
    {
        Console.WriteLine(a.Name + " is " + a.Age.ToString() + " years old.");
    }
    else
    {
        Console.WriteLine(a.Name + " is 999 years old.");
    }
            
}
```
从V2.0.1版开始，增加对更多虚方法和泛型方法的hook支持，使用.Net Standard 2.0编译，支持.NET 4.7+/6/8/10，与.net跨平台架构保持一致。 
如果有技术上的问题，请联系我扣扣252502568，长久交流。