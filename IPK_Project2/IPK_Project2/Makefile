ARGS :=

all: publish

build:
	dotnet build

publish:
	dotnet publish -o . -p:PublishSingleFile=true --self-contained true

run:
	dotnet run --project IPK_Project2.csproj -- $(ARGS)

clean:
	dotnet clean
	rm -rf ./bin ./obj
	rm -f ./ipk-sniffer
    
.PHONY: all build run clean