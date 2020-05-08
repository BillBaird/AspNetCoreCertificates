using System;
// See: https://youtrack.jetbrains.com/issue/RIDER-44218
namespace UnreachableCodeBug
{
    class Program
    {
        public static void Main(string[] args)
        {
            #nullable enable annotations
            SomeClass? someClass = GetRealInstance();
            if (someClass == null)
            {
                Console.WriteLine("Was null");         // Should be inaccessible
            }
            else
                Console.WriteLine("Was not null");    // Correct since someClass will always have a value

            someClass = GetNullInstance();
            if (someClass == null)
            {
                Console.WriteLine("Was null"); // InCorrect since someClass will always be null
            }
            else
                Console.WriteLine("Was not null");    // Should be inaccessible
        }

        private static SomeClass GetRealInstance()
            => new SomeClass {I = 1};
        
        private static SomeClass GetNullInstance()
            => null;
    }
    
    public class SomeClass
    {
        public int I { get; set; }
    }
}