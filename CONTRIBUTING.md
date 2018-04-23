# Contributing

Contributions are **welcome** and will be fully **credited**. This page details how to 
contribute and the expected code quality for all contributions.

## Pull Requests

We accept contributions via Pull Requests on [Github](https://github.com/lordelph/php-certificate-toolbox).

- **[PSR-2 Coding Standard](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-2-coding-style-guide.md)** - Check the code style with ``$ composer check-style`` and fix it with ``$ composer fix-style``.

- **Add tests!** - Your patch won't be accepted if it doesn't have tests.

- **Document any change in behaviour** - Make sure the `README.md` and any other relevant documentation are kept up-to-date.

- **Consider our release cycle** - We try to follow [SemVer v2.0.0](http://semver.org/). Randomly breaking public APIs is not an option.

- **Create feature branches** - Don't ask us to pull from your master branch.

- **One pull request per feature** - If you want to do more than one thing, send multiple pull requests.

- **Send coherent history** - Make sure each individual commit in your pull request is meaningful. If you had to make multiple intermediate commits while developing, please [squash them](http://www.git-scm.com/book/en/v2/Git-Tools-Rewriting-History#Changing-Multiple-Commit-Messages) before submitting.


## Running Tests

``` bash
$ composer test
```

## Exceptions

* All exceptions thrown by code in this package MUST implement `LEClientException`
* Custom exception classes SHOULD derive from standard base exceptions where appropriate
* a `LogicException` SHOULD be used for invalid use of methods or classses which would be
  fixable by the developer using the classes
* a `RuntimeException` SHOULD be used for problems which arise from unexpected external 
  conditions, such as an ACME API failure.
* It is not necessary to add code coverage for runtime exceptions - such code paths SHOULD
  be marked with `@codeCoverageIgnoreStart` / `@codeCoverageIgnoreEnd` markers
 
## Logging

The classes use a PSR-3 compatible logger. The following should be used as a guideline
for appropriate logging levels:

* `debug` is for maintainer use only. If an end-user has an issue, they should be asked to
  submit a report which contains a log with debug enabled. This should allow the interactions
  with the remote ACME API to be observed.
* `info` should record a general interaction which an outside observer would find interesting,
  typically, that a high level method of the main client class has been used.
* `notice` should record some expected change of state, e.g. a new order, new certificate etc 
* `warning` should record an unusual but handled problem, e.g. regenerating a private key
* `error` should record an unusual but unhandled problem
* `critical` should record any logic problem where the problem is likely correctable by the 
  code using these classes. It will usually be followed by a `LogicException`
* `alert` should record unexpected issues arising from ACME API interactions, and will
  generally be followed by a `RuntimeException`
* `emergency` should be used only when time is of the essence. This is not presently used
  but one example might be failure to renew a certificate when an existing certificate is
  known to be expiring soon




**Happy coding**!
