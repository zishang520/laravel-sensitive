<?php

namespace Sydante\LaravelSensitive;

use Illuminate\Support\Str;
use Sydante\LaravelSensitive\Exceptions\CacheException;
use Sydante\LaravelSensitive\Exceptions\FileReadException;

/**
 * 敏感词检查及过滤扩展包，采用 DFA 算法.
 *
 * @package Sydante\LaravelSensitive
 */
class Sensitive
{
    /**
     * 正则匹配：中日韩文、拉丁字母、数字.
     */
    private const REGEXP = '/[^\x{4E00}-\x{9FA5}\x{F900}-\x{FA2D}\x{0030}-\x{0039}\x{0041}-\x{005a}\x{0061}-\x{007a}]/u';

    /**
     * 替换字符串.
     *
     * @var string
     */
    private $replaceCode = '*';

    /**
     * 敏感词库集合.
     *
     * @var array
     */
    private $trieTreeMap = [];

    /**
     * 干扰因子集合.
     *
     * @var iterable
     */
    private $disturbList = [];

    /**
     * 配置.
     *
     * @var array|null
     */
    private $config;

    /**
     * 是否使用缓存.
     *
     * @var bool
     */
    private $useCache;

    /**
     * 缓存类.
     *
     * @var SensitiveCacheInterface
     */
    private $cache;

    /**
     * Sensitive constructor.
     *
     * @throws FileReadException
     * @throws CacheException
     */
    public function __construct(?array $config = null)
    {
        $this->config = $config;

        $this->useCache = $config['cache'] ?? false;

        if (isset($config['replace_code'])) {
            $this->setReplaceCode($config['replace_code']);
        }

        if (isset($config['disturbs'])) {
            $this->setDisturbs($config['disturbs']);
        }

        // 是否使用缓存
        if ($this->useCache) {
            // 缓存类
            $cacheCls = $config['cache_class'] ?? SensitiveCache::class;

            if (!class_exists($cacheCls)) {
                throw new CacheException('cache class not exists');
            }

            $cache = new $cacheCls();

            if ($cache instanceof SensitiveCacheInterface) {
                $cache->setKey($config['cache_key'] ?? md5(__CLASS__));

                $this->cache = $cache;

                // 有缓存就使用缓存
                if ($trieTreeMap = $cache->get()) {
                    $this->trieTreeMap = $trieTreeMap;
                    return;
                }
            } else {
                throw new CacheException('cache not implement SensitiveCacheInterface');
            }
        }

        // 没缓存就加载配置中的敏感词设置，并在使用缓存时更新缓存
        $this->resetTrieTreeMap()->saveTrieTreeMap();
    }

    /**
     * 设置替换字符串.
     */
    public function setReplaceCode(string $replaceCode): self
    {
        $this->replaceCode = $replaceCode;

        return $this;
    }

    /**
     * 设置干扰因子.
     */
    public function setDisturbs(iterable $disturbList = []): self
    {
        $this->disturbList = $disturbList;

        return $this;
    }

    /**
     * 如果使用缓存的话，保存当前敏感词库集合到缓存中.
     *
     * @throws CacheException
     */
    public function saveTrieTreeMap(): bool
    {
        if ($this->useCache) {
            if ($this->cache->set($this->trieTreeMap)) {
                return true;
            }

            throw new CacheException('save cache failed');
        }

        return false;
    }

    /**
     * 使用配置中的设置重置当前的敏感词库集合.
     *
     * @throws FileReadException
     */
    public function resetTrieTreeMap(): Sensitive
    {
        $this->emptyTrieTreeMap();

        $config = $this->config;

        if (isset($config['words'])) {
            $this->addWords($config['words']);
        }

        if (isset($config['file'])) {
            $this->addWordsFromFile($config['file']);
        }

        return $this;
    }

    /**
     * 清空敏感词库集合.
     */
    public function emptyTrieTreeMap(): Sensitive
    {
        $this->trieTreeMap = [];

        return $this;
    }

    /**
     * 清理敏感词库集合缓存.
     *
     * @throws CacheException
     */
    public function clearCache(): bool
    {
        if ($this->useCache) {
            if ($this->cache->clear()) {
                return true;
            }

            throw new CacheException('clear cache failed');
        }

        return false;
    }

    /**
     * 添加敏感词.
     */
    public function addWords(iterable $wordsList): Sensitive
    {
        foreach ($wordsList as $words) {
            $this->addToTree($words);
        }

        return $this;
    }

    /**
     * 从文件中读取并添加敏感词.
     *
     * @throws FileReadException
     */
    public function addWordsFromFile(string $filename): Sensitive
    {
        foreach ($this->getWordsFromFile($filename) as $words) {
            $this->addToTree($words);
        }

        return $this;
    }

    /**
     * 过滤敏感词.
     */
    public function filter(string $text): string
    {
        $wordsList = $this->search($text, true);

        if (!$wordsList->valid() || is_null($wordsList->key())) {
            return $text;
        }

        return strtr($text, iterator_to_array($wordsList));
    }

    /**
     * 查找对应敏感词.
     */
    public function search(string $text, bool $hasReplace = false): \Generator
    {
        $textLength = mb_strlen($text, 'utf-8');
        for ($i = 0; $i < $textLength; ++$i) {
            $wordLength = 0;
            $trieTree = &$this->trieTreeMap;
            $beginIndex = $i;
            $replace_str = '';
            $is_conjunction = false;
            for ($index = $beginIndex; $index < $textLength; ++$index) {
                $original_word = mb_substr($text, $index, 1, 'utf-8');
                $word = Transform::BIG5_GB2312[$original_word] ?? $original_word; // 转为简体

                if (!isset($trieTree[$word])) {
                    // 判断已经有匹配词汇了
                    if ($wordLength > 0) {
                        // 连词搜索
                        if (!$is_conjunction && ($word !== '+') && isset($trieTree['+'])) {
                            $is_conjunction = true;
                            $conjunction = $this->searchConjunction($text, $trieTree['+'], $index, $textLength, $hasReplace);
                            if ($conjunction->valid() && !is_null($conjunction->key())) {
                                if ($hasReplace) {
                                    yield mb_substr($text, $i, $wordLength, 'utf-8') => $replace_str;
                                } else {
                                    yield mb_substr($text, $i, $wordLength, 'utf-8');
                                }
                                foreach ($conjunction as $key => $value) {
                                    if ($hasReplace) {
                                        yield $key => $value;
                                    } else {
                                        yield $value;
                                    }
                                }
                            }
                        }
                        if ($this->isDisturb($word)) {
                            ++$wordLength;
                            $replace_str .= $word;
                            continue;
                        }
                    }
                    break;
                }

                ++$wordLength;

                if ($trieTree[$word] !== false) {
                    $trieTree = &$trieTree[$word];
                    $replace_str .= $this->replaceCode;
                } else {
                    $i += $wordLength - 1;
                    $replace_str .= $this->replaceCode; // 最后的一个字符替换
                    if ($hasReplace) {
                        yield mb_substr($text, $beginIndex, $wordLength, 'utf-8') => $replace_str;
                    } else {
                        yield mb_substr($text, $beginIndex, $wordLength, 'utf-8');
                    }
                    break;
                }
            }
        }
    }

    /**
     * 判断是否存在敏感词.
     * @copyright (c) zishang520 All Rights Reserved
     */
    public function check(string $text): bool
    {
        $wordsList = $this->search($text);

        if (!$wordsList->valid() || is_null($wordsList->key())) {
            return false;
        }
        return true;
    }

    /**
     * 连词搜索.
     * @copyright (c) zishang520 All Rights Reserved
     */
    protected function searchConjunction(string &$text, array &$trieTreeMap, int $startIndex, int $textLength, bool $hasReplace = false): \Generator
    {
        for ($i = $startIndex; $i < $textLength; ++$i) {
            $wordLength = 0;
            $trieTree = &$trieTreeMap;
            $beginIndex = $i;
            $replace_str = '';
            $is_conjunction = false;
            for ($index = $beginIndex; $index < $textLength; ++$index) {
                $original_word = mb_substr($text, $index, 1, 'utf-8');
                $word = Transform::BIG5_GB2312[$original_word] ?? $original_word; // 转为简体

                if (!isset($trieTree[$word])) {
                    // 判断已经有匹配词汇了
                    if ($wordLength > 0) {
                        // 连词搜索
                        if (!$is_conjunction && ($word !== '+') && isset($trieTree['+'])) {
                            $is_conjunction = true;
                            $conjunction = $this->searchConjunction($text, $trieTree['+'], $index, $textLength, $hasReplace);
                            if ($conjunction->valid() && !is_null($conjunction->key())) {
                                if ($hasReplace) {
                                    yield mb_substr($text, $i, $wordLength, 'utf-8') => $replace_str;
                                } else {
                                    yield mb_substr($text, $i, $wordLength, 'utf-8');
                                }
                                foreach ($conjunction as $key => $value) {
                                    if ($hasReplace) {
                                        yield $key => $value;
                                    } else {
                                        yield $value;
                                    }
                                }
                            }
                        }
                        if ($this->isDisturb($word)) {
                            ++$wordLength;
                            $replace_str .= $word;
                            continue;
                        }
                    }
                    break;
                }

                ++$wordLength;

                if ($trieTree[$word] !== false) {
                    $trieTree = &$trieTree[$word];
                    $replace_str .= $this->replaceCode;
                } else {
                    $i += $wordLength - 1;
                    $replace_str .= $this->replaceCode; // 最后的一个字符替换
                    if ($hasReplace) {
                        yield mb_substr($text, $beginIndex, $wordLength, 'utf-8') => $replace_str;
                    } else {
                        yield mb_substr($text, $beginIndex, $wordLength, 'utf-8');
                    }
                    break 2; // 结束跳出本次的连词搜索
                }
            }
        }
    }

    /**
     * 将敏感词加入敏感词库集合中.
     */
    private function addToTree(string $words): void
    {
        $words = str_replace([' ', "\t", "\0", "\x0B"], '', trim($words, " \t\n\r\0\x0B'\"`"));

        if ($words === '' || $words[0] === '#') {
            return;
        }

        $nowWords = &$this->trieTreeMap;

        foreach ($this->makeIterator($words) as $word) {
            if (!isset($nowWords[$word])) {
                $nowWords[$word] = false;
            }

            $nowWords = &$nowWords[$word];
        }
    }

    /**
     * 使用生成器方式读取文件.
     *
     * @throws FileReadException
     */
    private function getWordsFromFile(string $filename): \Generator
    {
        if (!file_exists($filename)) {
            throw new FileReadException("file [{$filename}] not exists");
        }

        if (!($handle = fopen($filename, 'rb'))) {
            throw new FileReadException('read file failed');
        }

        while (!feof($handle)) {
            yield fgets($handle);
        }

        fclose($handle);
    }

    /**
     * 是否为干扰因子.
     */
    private function isDisturb(string $word): bool
    {
        return preg_match(self::REGEXP, $word) || Str::contains($word, $this->disturbList);
    }

    /**
     * 生成器.
     * @copyright (c) zishang520 All Rights Reserved
     */
    private function makeIterator(string $str): \Generator
    {
        yield from mb_str_split($str, 1, 'utf-8');
    }
}
